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
#include "timer.h"


namespace tracer
{
union machine_word {
	long num;
	char buf[sizeof(long)];
};




bool operator<(const s_proc_inf& left, const s_proc_inf& right)
{
	return left.pid < right.pid;
}

bool operator<(const pid_t& left, const s_proc_inf& right)
{
	return left < right.pid;
}
bool operator<(const s_proc_inf& left, const pid_t& right)
{
	return left.pid < right;
}

static void alrm_handler(int) 
{}

/* 
	Used to set special option to the new attached by ptrace process
*/
static void configure_attach(pid_t pid) 
{
	if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) == -1) 
	{
		throw(std:: runtime_error("configure_process: PTRACE_INTERRUPT failed"));
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
			throw(std:: runtime_error("configure_process: tracee is dead")); // process was attached but died before wait_for_syscall()
		}

		if ((status>>8) == (SIGTRAP | (PTRACE_EVENT_STOP << 8))) 
		{
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, OPTIONS) == -1)
				throw(std:: runtime_error("configure_process: PTRACE_SETOPTIONS failed"));
			if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1)
				throw(std:: runtime_error("configure_process: PTRACE_SYSCALL failed"));			
			break;
		}

		ptrace(PTRACE_CONT, pid, 0, WSTOPSIG(status)); // inject all signals (which was concurrently sent) untill catching PTRACE_EVENT_STOP
	}
}

/* 
	This function is used to make ptrace attach and set options 
*/
static void attach_process(pid_t pid) 
{
	if (ptrace(PTRACE_SEIZE, pid, 0, 0) == -1) 
	{
		throw(std:: runtime_error("attach_process: process attaching failed"));
	}
	
	try
	{
		configure_attach(pid);
	}
	catch (const std::exception error)
	{
		DPRINTF9("%s", error.what());
		ptrace(PTRACE_DETACH, pid, NULL, NULL); // this is not necessary because only reason that configure_attach failed is 
												// that tracee terminate but may be in the future there will be new reasons
		throw(std:: runtime_error("attach_process: process was attached successfuly but configure_attach failed"));
	}
}


/* 
	Return length of string contained in traced process
	this is harder because traced process has its own address space, 
	ptrace provide special commands to solve this
*/
static unsigned int get_strlen_arg(pid_t pid, unsigned long long int tracee_ptr)  
{
	int n = 0;
	char* ptr = NULL;
	union machine_word word;
	if (tracee_ptr == 0) 
		throw(std:: runtime_error("get_strlen_arg: nullptr was passed"));
	while(1) 
	{
		if ((word.num = ptrace(PTRACE_PEEKDATA, pid, tracee_ptr + n, NULL)) == -1)
		{
			throw(std:: runtime_error("get_strlen_arg: PTRACE_PEEKDATA failed"));
		}
		if ((ptr = static_cast <char*> (memchr(word.buf, '\0', sizeof(long))))) 
		{
			n += ptr - word.buf; 
			break;
		}
		n += sizeof(long);
	}
	return n;
}

/* 
	Write string in str argument from tracee_ptr 
*/

static int get_str(pid_t pid, unsigned long long int tracee_ptr, char* str)
{
	int n = 0;
	char* ptr = NULL;
	union machine_word word;
	if (tracee_ptr == 0) 
		throw(std:: runtime_error("get_strlen_arg: nullptr was passed"));
	while(1) 
	{
		if ((word.num = ptrace(PTRACE_PEEKDATA, pid, tracee_ptr + n, NULL)) == -1)
			throw(std:: runtime_error("get_strlen_arg: PTRACE_PEEKDATA failed"));
		if ((ptr =static_cast<char*> (memchr(word.buf, '\0', sizeof(size_t))))) 
		{
			memcpy(str + n, word.buf, ptr - word.buf + 1); 
			break;
		}
		memcpy(str + n, word.buf, sizeof(size_t));
		n += sizeof(size_t);
	}
	return 0;
}

/* 
	This is a function which user can call and get allocated string same as tracee_ptr,
	but this string is placed in users address space
*/
static char* alloc_and_get_arg_string(pid_t pid, unsigned long long tracee_ptr) 
{
	int n = get_strlen_arg(pid, tracee_ptr) + 1;
	DPRINTF9("n = %d", n);


	char* str = NULL;
	str = (char*) malloc(n);

	try
	{
		get_str(pid, tracee_ptr, str);
	}
	catch (const std::exception& error) 
	{
		DPRINTF9("%s", error.what());
		free(str);
		str = NULL;
		throw (std:: runtime_error("getting argument from tracee registers fails"));
	}
	DPRINTF9("str = '%s'", str);
	return str;
}

/*
	Before start you can change this part to control what Process IDs will be traced by this process
	all process connected from /proc will be checked using this function
*/
static int check_pid(pid_t pid, pid_t my_pid)
{
	if (pid < my_pid || pid == my_pid) // first can be changed, second condition should stay just in case
		return 0;
	return 1;
}

static char* get_executable_path(pid_t pid) // realpath can be used to get real path of link /proc/<PID>/exe
{
	std::string path = std::to_string(pid);
	path = "/proc/" + path + "/exe";

	char* exec_path = realpath(path.c_str(), NULL);
	if (!exec_path)
	{
		if (errno == ENOENT)
			throw std:: runtime_error("get_executable_path: realpath fails no such file");
		else
			throw std:: runtime_error("get_executable_path: realpath fails system error");
	}
	return exec_path;
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
		ret.reason = ProcessChangeStateReason::TIMEOUT;
		return ret;
	}

	if (pid == -1 && errno == ECHILD) 
	{
		ret.reason = ProcessChangeStateReason::ALL_DEAD;
		return ret;
	}

	if (pid == -1) 
	{
		ret.reason = ProcessChangeStateReason::ERROR;
		return ret;
	}

	if (WIFEXITED(status)) // tracee unexpectively died
	{
		ret.pid = pid;
		ret.reason = ProcessChangeStateReason::DEAD;
		return ret;
	}

	if (!WIFSTOPPED(status)) 
	{
		ret.reason = ProcessChangeStateReason::ERROR;
		return ret;
	}

	if (WSTOPSIG(status) == (SIGTRAP | 0x80))  // We are sure this is a syscall
	{
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			ret.reason = ProcessChangeStateReason::ERROR;
		}
		else 
			ret.reason = ProcessChangeStateReason::SYSCALL;

		ret.pid = pid;
		ret.registers = regs;

		return ret;
	}
	if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_FORK << 8)) 
		|| (status >> 8) == (SIGTRAP | (PTRACE_EVENT_VFORK << 8)) 
		|| (status >> 8) == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) 
	{
		ret.reason = ProcessChangeStateReason::FORK;
		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &ret.pid) == -1) 
		{
			ret.reason = ProcessChangeStateReason::ERROR;
			return ret;
		}

		std::lock_guard<std::recursive_mutex> lock_guard(mutex_);

		if (procs_inf_.find(s_proc_inf{pid, 0}) == procs_inf_.end()) 
		{
			ret.pid = 0;
			long options = OPTIONS;
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, options) == -1 
				|| ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) 
			{
				ret.reason = ProcessChangeStateReason::ERROR;
			}
			return ret;
		}

		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) 
		{
			ret.reason = ProcessChangeStateReason::ERROR;
		}
		return ret;
	}

	if (status >> 8 == PTRACE_EVENT_STOP << 8)
	{
		ret.reason = ProcessChangeStateReason::GROUPSTOP;
		ret.pid = pid;
		if (WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP
			|| WSTOPSIG(status) == SIGTTIN || WSTOPSIG(status) == SIGTTOU)
		{
			if (ptrace(PTRACE_LISTEN, pid, NULL, WSTOPSIG(status)) == -1)
			{
				ret.reason = ProcessChangeStateReason::ERROR;
				return ret;
			}
		}
		else {
			if (ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(status)) == -1)
			{
				ret.reason = ProcessChangeStateReason::ERROR;
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
	ret.reason = ProcessChangeStateReason::SIGNAL;

	return ret;
}

void Tracer:: process_syscall(s_state_info event)
{
	char* path = NULL;
	char* exec_path = NULL;
	try
	{
		exec_path = get_executable_path(event.pid);
	}
	catch(std::exception error)
	{
		DPRINTF9("%s", error.what());
		exec_path = NULL;
	}

	switch(event.registers.orig_rax)
	{
		case event::OPEN:
		{
			try
			{
				path = alloc_and_get_arg_string(event.pid, event.registers.rdi);
			}
			catch(const std::exception& exc)
			{
				DPRINTF9("%s", exc.what());
				path = strdup("?");
			}

			event::data::Open data_open;
			data_open.executable_path = exec_path;
			data_open.data_path = path;

			IPRINTF("%u: onEvent(%llu/%s, path='%s' executable path ='%s') start",
				event.pid, event.registers.orig_rax,
				event::toString(event.registers.orig_rax),
				data_open.data_path, data_open.executable_path);

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
			try
			{
				path = alloc_and_get_arg_string(event.pid, event.registers.rdi);
			}
			catch(const std::exception& exc)
			{
				DPRINTF9("%s", exc.what());
				path = strdup("?");
			}

			event::data::Exec data_exec;
			data_exec.parent_path = exec_path;
			data_exec.child_path = path;

			IPRINTF("%u: onEvent(%llu/%s, child path='%s' parent path ='%s') start",
				event.pid, event.registers.orig_rax,
				event::toString(event.registers.orig_rax),
				data_exec.child_path, data_exec.parent_path);

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
			try
			{
				path = alloc_and_get_arg_string(event.pid, event.registers.rsi);
			}
			catch(const std::exception& exc)
			{
				DPRINTF9("%s", exc.what());
				path = strdup("?");
			}

			event::data::Open data_open;
			data_open.executable_path = exec_path;
			data_open.data_path = path;

			IPRINTF("%u: onEvent(%llu/%s, path='%s' executable path ='%s') start",
				event.pid, event.registers.orig_rax,
				event::toString(event.registers.orig_rax),
				data_open.data_path, data_open.executable_path);

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

	switch (event.reason) 
	{
		case ProcessChangeStateReason::SIGNAL:
		{
			IPRINTF("%d: Signal %d", event.pid, event.signum);
			break;
		}
		case ProcessChangeStateReason::TIMEOUT:
		{
			IPRINTF("TO");
			break;
		}
		case ProcessChangeStateReason::ERROR:
		{
			IPRINTF("%d: Error %d", event.pid, errno);
			break;
		}
		case ProcessChangeStateReason::DEAD:
		{
			IPRINTF("%d: dead", event.pid);
			{
				std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				procs_inf_.erase(procs_inf_.find(s_proc_inf{event.pid, 0}));
			}
			break;
		}
		case ProcessChangeStateReason::ALL_DEAD:
		{
			IPRINTF("All tracees are dead");
			sleep(2);
			break;
		}
		case ProcessChangeStateReason::GROUPSTOP:
		{
			IPRINTF("%u: onEvent groupstop", event.pid);
			break;
		}
		case ProcessChangeStateReason::FORK:
			if (event.pid == 0) 
			{
				break; // TODO: this should restart inside wait_for_syscall()
			}
			IPRINTF("onEvent fork: child=%d", event.pid);

			/*{
				std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				IPRINTF("2 Attach = %d", event.pid);
				procs_inf_.insert(s_proc_inf{event.pid, 0});    			
			}*/

			break;
		case ProcessChangeStateReason::SYSCALL:
		{
			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);

			auto it = procs_inf_.find(s_proc_inf{event.pid, 0});
			if (it == procs_inf_.end()) 
			{
				std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				IPRINTF("2 Attach = %d", event.pid);
				procs_inf_.insert(s_proc_inf{event.pid, 0});
				it = procs_inf_.find(s_proc_inf{event.pid, 0});
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

			procs_inf_.erase(it);
			procs_inf_.insert(s_proc_inf{it->pid, in_syscall});

			if (ptrace(PTRACE_SYSCALL, event.pid, NULL, NULL) == -1)
			{
				EPRINTF("PTRACE_SYSCALL");
				exit(0);
			}
		}
		break;
		default:
		{
			EPRINTF("Strange event.reason=%d", event.reason);
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
	
	routine_tid_ = syscall(SYS_gettid);

	PeriodicTimer timer(routine_tid_); 	// this class used to emulate exit from wait by timeout
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
				try
				{
					update_pids();
				}
				catch(const std::exception error)
				{
					DPRINTF9("%s", error.what());
				}
			}
		}
		count++;
		s_state_info event = wait_untill_event();
		if (event.reason == ProcessChangeStateReason::ALL_DEAD)
		{
			try
			{
				update_pids();
			}
			catch(const std::exception error)
			{
				DPRINTF9("%s", error.what());
			}
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
		struct s_proc_inf s_inf;
		s_inf.pid = strtol(s_dir_ptr->d_name, &ptr, 10);

		if (ptr && s_dir_ptr->d_name != ptr && *ptr == '\0' && s_inf.pid != my_pid) 
		{ 
			if (procs_inf_.find(s_inf) == procs_inf_.end() && check_pid(s_inf.pid, my_pid))
			{
				try
				{
					attach_process(s_inf.pid);
				} 
				catch(std::exception error)
				{
					DPRINTF9("%s", error.what());
				}
				
				s_inf.in_syscall = 0;
				IPRINTF("1 Attach = %d", s_inf.pid);
				procs_inf_.insert(s_inf);
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
