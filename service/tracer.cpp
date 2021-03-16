#define ABSOLUTELY_NOT_A_SYSCALL -1
#define UPDATE_LOOP 100
#define OPTIONS PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>


#include <set>
#include <iostream>
#include <thread>
#include <mutex>

#include "debug.h"
#include "tracer.h"
#include "event.h"
#include "alarm.h"


namespace tracer
{
union machine_word {
	long num;
	char buf[sizeof(long)];
};




bool operator<(const s_pid_inf& left, const s_pid_inf& right)
{
	return left.pid < right.pid;
}

bool operator<(const pid_t& left, const s_pid_inf& right)
{
	return left < right.pid;
}
bool operator<(const s_pid_inf& left, const pid_t& right)
{
	return left.pid < right;
}

void alrm_handler(int) 
{}

int config_attach(pid_t pid)
{
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) 
	{
		return -1;
	}
	int status;
	int res = 0;

	while (1) 
	{
		res = waitpid(pid, &status, __WALL);
		if (res == -1 && errno == EINTR) 
			continue;
		else if (res == -1) 
		{
			errno = ESRCH;
			return -1; // process was attached but died before wait_for_syscall()
		}

		if ((status>>8) == (SIGTRAP | (PTRACE_EVENT_STOP << 8))) 
		{
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, OPTIONS) == -1 
				|| ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1)
				return -1;
			
			break;
		}

		ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)); // inject all signals (which was concurrently sent) untill catching PTRACE_EVENT_STOP
	}
	return 0;
}

int attach_process(pid_t pid) 
{
	if (ptrace(PTRACE_SEIZE, pid, 0, 0) == -1) 
	{
		return -1;
	}
	
	int res = config_attach(pid);
	if (res == -1)
		EPRINTF("config_attach failed");
	return res;
}

int get_strlen_arg(pid_t pid, unsigned long long int tracee_ptr)  
{
	int n = 0;
	char* ptr = NULL;
	union machine_word word;
	if (tracee_ptr == 0) 
		return -1;
	while(1) 
	{
		if ((word.num = ptrace(PTRACE_PEEKDATA, pid, tracee_ptr + n, NULL)) == -1)
			return -1;
		if ((ptr = static_cast <char*> (memchr(word.buf, '\0', sizeof(long))))) 
		{
			n += ptr - word.buf; 
			break;
		}
		n += sizeof(long);
	}
	return n;
}

int get_str(pid_t pid, unsigned long long int tracee_ptr, char* str)
{
	int n = 0;
	char* ptr = NULL;
	union machine_word word;
	if (tracee_ptr == 0) 
		return -1;
	while(1) 
	{
		if ((word.num = ptrace(PTRACE_PEEKDATA, pid, tracee_ptr + n, NULL)) == -1)
			return -1;
		if ((ptr =static_cast<char*> (memchr(word.buf, '\0', sizeof(size_t))))) 
		{
			memcpy(str, word.buf, ptr - word.buf + 1); 
			break;
		}
		n += sizeof(size_t);
		memcpy(str, word.buf, sizeof(size_t));
	}
	return 0;
}

char* alloc_and_get_arg_string(pid_t pid, unsigned long long tracee_ptr) 
{
	int n = get_strlen_arg(pid, tracee_ptr) + 1;
	if (n < 0)
	{
		DPRINTF9("%d", n);
		throw (std:: runtime_error("negative length of string"));
	}

	char* str = NULL;
	str = (char*) malloc(n);

	if (get_str(pid, tracee_ptr, str))
		throw (std:: runtime_error("getting argument from tracee registers fails"));
	return str;
}

/*before start you can change this part to control what pid's will be traced by this process*/
int check_pid(pid_t pid, pid_t my_pid)
{
	if (pid < my_pid || pid == my_pid) // first can be changed, second condition should stay just in case
		return 0;
	return 1;
}

char* get_executable_path(pid_t) // realpath can be used to get real path of link /proc/<PID>/exe
{
	return NULL;
}

s_state_info Tracer:: wait_untill_event()
{

	struct s_state_info ret;
	pid_t pid = 0;
	int status = 0;

	struct user_regs_struct regs;
	pid = waitpid(-1, &status, __WALL);

	if (pid == -1 && errno == EINTR) 
	{
		ret.retval = Retval::TIMEOUT;
		return ret;
	}

	if (pid == -1 && errno == ECHILD) 
	{
		ret.retval = Retval::ALL_DEAD;
		return ret;
	}

	if (pid == -1) 
	{
		ret.retval = Retval::ERROR;
		return ret;
	}

	if (WIFEXITED(status)) // tracee unexpectively died
	{
		ret.pid = pid;
		ret.retval = Retval::DEAD;
		return ret;
	}

	if (!WIFSTOPPED(status)) 
	{
		ret.retval = Retval::ERROR;
		return ret;
	}

	if (WSTOPSIG(status) == (SIGTRAP | 0x80))  // We are sure this is a syscall
	{
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			ret.retval = Retval::ERROR;
		}
		else 
			ret.retval = Retval::SYSCALL;

		ret.pid = pid;
		ret.registers = regs;

		return ret;
	}
	if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) 
		|| (status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) 
		|| (status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) 
	{
		ret.retval = Retval::FORK;
		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &ret.pid) == -1) 
		{
			ret.retval = Retval::ERROR;
			return ret;
		}

		std:: lock_guard<std:: recursive_mutex> lock_guard(mutex_);

		if (pids_.find(s_pid_inf{pid, 0}) == pids_.end()) 
		{
			ret.pid = 0;
			long options = OPTIONS;
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, options) == -1 
				|| ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) 
			{
				ret.retval = Retval::ERROR;
			}
			return ret;
		}

		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) 
		{
			ret.retval = Retval::ERROR;
		}
		return ret;
	}

	if (status >> 8 == PTRACE_EVENT_STOP << 8)
	{
		ret.retval = Retval::GROUPSTOP;
		ret.pid = pid;
		if (WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP
			|| WSTOPSIG(status) == SIGTTIN || WSTOPSIG(status) == SIGTTOU)
		{
			if (ptrace(PTRACE_LISTEN, pid, NULL, WSTOPSIG(status)) == -1)
			{
				ret.retval = Retval::ERROR;
				return ret;
			}
		}
		else {
			if (ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(status)) == -1)
			{
				ret.retval = Retval::ERROR;
				return ret;	
			}
		}
		return ret;
	}

	siginfo_t sig_info;
	ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig_info);
	ptrace(PTRACE_SYSCALL, pid, 0, sig_info.si_signo);
	ret.pid = pid;
	ret.signum = sig_info.si_signo;
	ret.retval = Retval::SIGNAL;

	return ret;
}

void Tracer:: process_syscall(s_state_info event)
{
	char* path = NULL;
	char* exec_path = NULL;

	switch(event.registers.orig_rax)
	{
		case event::OPEN:
		{
			path = alloc_and_get_arg_string(event.pid, event.registers.rdi);
			exec_path = get_executable_path(event.pid);

			event::data::Open data_open;
			data_open.executable_path = exec_path;
			data_open.data_path = path;

			IPRINTF("%u: onEvent(%llu/%s, path='%s') start",
				event.pid, event.registers.orig_rax,
				event::toString(event.registers.orig_rax),
				data_open.data_path);

			if (!tracerEventObserver_.onEvent(event::Type::OPEN, &data_open))
			{
				IPRINTF("%u: Syscall denied", event.pid);
				event.registers.orig_rax = ABSOLUTELY_NOT_A_SYSCALL;
				ptrace(PTRACE_SETREGS, event.pid, NULL, &event.registers);
			}

			break;
		}
		case event::EXEC:
		{
			path = alloc_and_get_arg_string(event.pid, event.registers.rdi);
			exec_path = get_executable_path(event.pid);

			event::data::Exec data_exec;
			data_exec.parent_path = exec_path;
			data_exec.child_path = path;

			IPRINTF("%u: onEvent(%llu/%s, path='%s') start",
				event.pid, event.registers.orig_rax,
				event::toString(event.registers.orig_rax),
				data_exec.child_path);

			if (!tracerEventObserver_.onEvent(event::Type::EXEC, &data_exec))
			{
				IPRINTF("%u: Syscall denied", event.pid);
				event.registers.orig_rax = ABSOLUTELY_NOT_A_SYSCALL;
				ptrace(PTRACE_SETREGS, event.pid, NULL, &event.registers);
			}
			break;	
		}
		case event::OPENAT:
		{
			path = alloc_and_get_arg_string(event.pid, event.registers.rsi);
			exec_path = get_executable_path(event.pid);

			event::data::Open data_open;
			data_open.executable_path = exec_path;
			data_open.data_path = path;

			IPRINTF("%u: onEvent(%llu/%s, path='%s') start",
				event.pid, event.registers.orig_rax,
				event::toString(event.registers.orig_rax),
				data_open.data_path);

			if (!tracerEventObserver_.onEvent(event::Type::OPENAT, &data_open))
			{
				IPRINTF("%u: Syscall denied", event.pid);
				event.registers.orig_rax = ABSOLUTELY_NOT_A_SYSCALL;
				ptrace(PTRACE_SETREGS, event.pid, NULL, &event.registers);
			}
			break;
		}
		default:
		{
			IPRINTF("%u: onEvent(%llu/%s) start",
				event.pid, event.registers.orig_rax,
				event::toString(event.registers.orig_rax));

			if (!tracerEventObserver_.onEvent(event::Type::UNKNOWN, NULL)) 
			{
				IPRINTF("%u: Syscall denied", event.pid);
				event.registers.orig_rax = ABSOLUTELY_NOT_A_SYSCALL;
				ptrace(PTRACE_SETREGS, event.pid, NULL, &event.registers);
			}
			break;
		}
	}

	free(path);
	free(exec_path);
}

void Tracer:: process_event(s_state_info event)
{
	{
		std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
		if (shutdown_)
		{
			return;
		}
	}

	switch (event.retval) 
	{
		case Retval::SIGNAL:
		{
			IPRINTF("%d: Signal %d", event.pid, event.signum);
			break;
		}
		case Retval::TIMEOUT:
		{
			IPRINTF("TO");
			break;
		}
		case Retval::ERROR:
		{
			IPRINTF("%d: Error %d", event.pid, errno);
			break;
		}
		case Retval::DEAD:
		{
			IPRINTF("%d: dead", event.pid);
			{
				std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				pids_.erase(pids_.find(s_pid_inf{event.pid, 0}));
			}
			break;
		}
		case Retval::ALL_DEAD:
		{
			IPRINTF("All tracees are dead");
			sleep(2);
			break;
		}
		case Retval::GROUPSTOP:
		{
			IPRINTF("%u: onEvent groupstop", event.pid);
			break;
		}
		case Retval::FORK:
			if (event.pid == 0) 
			{
				break; // TODO: this should restart inside wait_for_syscall()
			}
			IPRINTF("onEvent fork: child=%d", event.pid);

			/*{
				std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				IPRINTF("2 Attach = %d", event.pid);
				pids_.insert(s_pid_inf{event.pid, 0});    			
			}*/

			break;
		case Retval::SYSCALL:
		{
			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);

			auto it = pids_.find(s_pid_inf{event.pid, 0});
			if (it == pids_.end()) 
			{
				std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				IPRINTF("2 Attach = %d", event.pid);
				pids_.insert(s_pid_inf{event.pid, 0});
				it = pids_.find(s_pid_inf{event.pid, 0});
			}

			if (event.registers.orig_rax == (unsigned long) ABSOLUTELY_NOT_A_SYSCALL) 
			{
				event.registers.rax = -EPERM;
				ptrace(PTRACE_SETREGS, event.pid, NULL, event.registers);
			}

			int in_syscall = 0;
			if (it->in_syscall == 0) 
			{
				in_syscall = 1;

				process_syscall(event);
			}
			else 
			{
				in_syscall = 0;
				
				IPRINTF("%u: onEvent(%llu/%s) = %lld",
					event.pid, event.registers.orig_rax,
					event::toString(event.registers.orig_rax),
					event.registers.rax);

			}

			pids_.erase(it);
			pids_.insert(s_pid_inf{it->pid, in_syscall});

			if (ptrace(PTRACE_SYSCALL, event.pid, NULL, NULL) == -1)
			{
				EPRINTF("PTRACE_SYSCALL");
				exit(0);
			}
		}
		break;
		default:
		{
			EPRINTF("Strange event.retval=%d", event.retval);
		}
	}
}

void Tracer:: run_routine()
{
	struct sigaction act, old_act;
	act.sa_handler = alrm_handler;
	act.sa_flags = 0;
	sigemptyset(&act.sa_mask);
	sigaction(SIGALRM, &act, &old_act);
	
	{
		std:: lock_guard<std:: recursive_mutex> lock_guard(mutex_);
		routine_tid_ = syscall(SYS_gettid);
	}
	Alarm alarm_clock(routine_tid_);

	int count = 0;
	while(1) 
	{
		{
			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
			if (shutdown_)
			{
				routine_tid_ = -1;
				return;
			}
			if (UPDATE_LOOP > 0 && !(count %= UPDATE_LOOP))
			{
				update_pids();
			}
		}
		count++;
		s_state_info event = wait_untill_event();
		if (event.retval == Retval::ALL_DEAD)
		{
			update_pids();
		}
		process_event(event);
	}
}

/*void Tracer:: run_watch()
{	
	int tid = 0;
	while (tid <= 0)
	{
		sleep(1);
		std:: lock_guard<std:: recursive_mutex> lock_guard(mutex_);
		tid = routine_tid_;
		if (shutdown_)
			break;
	}

	while (1)
	{ 	
		if (routine_tid_ == -1)
		{
			break;
		}
		syscall(SYS_tkill, tid, SIGALRM);
		sleep(7);
	}

}*/

void Tracer:: run_proxy(void* self)
{
	try
	{
		static_cast<Tracer*>(self)->run_routine();
	}
	catch (const std::exception& e)
	{
		EPRINTF("Error in routine: %s", e.what());
		return;
	}
	catch (...)
	{
		EPRINTF("Error in routine: unexpected");
		return;
	}
}

void Tracer:: update_pids()
{
	struct dirent* s_dir_ptr = NULL;
	char* ptr = NULL;
	DIR* dir_ptr = opendir("/proc");
	if (!dir_ptr)
		throw std:: runtime_error("cannot open /proc directory for reading"); 

	pid_t my_pid = getpid();
	
	while ((s_dir_ptr = readdir(dir_ptr))) 
	{
		struct s_pid_inf s_inf;
		s_inf.pid = strtol(s_dir_ptr->d_name, &ptr, 10);

		if (ptr && s_dir_ptr->d_name != ptr && *ptr == '\0' && s_inf.pid != my_pid) 
		{ 
			if (pids_.find(s_inf) == pids_.end() && check_pid(s_inf.pid, my_pid))
			{
				if (attach_process(s_inf.pid)) 
				{
					perror("Attach:" );
				}
				else 
				{
					s_inf.in_syscall = 0;
					IPRINTF("1 Attach = %d", s_inf.pid);
					pids_.insert(s_inf);
				}
			}
		}
	}

	closedir(dir_ptr);
}

Tracer:: Tracer(event::source::Observer& tracerEventObserver):
	tracerEventObserver_(tracerEventObserver),
	routine_thread_(std::thread(run_proxy, this))
{
	DPRINTF9("'Tracer' created");
} 

Tracer:: ~Tracer()
{
	DPRINTF9("stopping 'Tracer' thread");
	{
		std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
		shutdown_ = true;
	}

	DPRINTF9("joining 'routine'");
	routine_thread_.join();
	DPRINTF9("destroying 'Tracer'");
}

} //tracer
