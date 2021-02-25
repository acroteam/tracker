
#include <stdio.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>

//#define _GNU_SOURCE
#include <sys/syscall.h>


#include <set>
#include <iostream>
#include <thread>
#include <mutex>

#include "debug.h"
#include "tracer.h"
#include "event.h"




#define ABSOLUTELY_NOT_A_SYSCALL 100000
#define UPDATE_LOOP 50
//#define TOUT 2


union machine_word {
	long num;
	char buf[sizeof(long)];
};





enum except
{
	OPENDIR,
};

enum retval 
{
	ERROR,
	SYSCALL,
	DEAD,
	ALL_DEAD,
	SIGNAL,
	GROUPSTOP,
	FORK,
	TIMEOUT
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


/*void alrm_handler(int) 
{
}*/

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

		if ((WSTOPSIG(status) == SIGTRAP )| (PTRACE_EVENT_STOP << 8)) 
		{
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK) == -1 || ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1)
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
	
	return config_attach(pid);
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
		if (!(ptr = static_cast <char*> (memchr(word.buf, '\0', sizeof(size_t))))) 
		{
			n += ptr - word.buf; 
			break;
		}
		n += sizeof(size_t);
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
		return NULL;

	char* str = new char[n];
	if (get_str(pid, tracee_ptr, str))
		return NULL;
	return str;
}	


/*before start you can change this part to control what pid's will be traced by this process*/
int check_pid(pid_t pid)
{

	if (pid < getpid() || pid == getpid()) // first can be changed, second condition should stay just in case
		return 0;
	return 1;
}








s_state_info Tracer:: wait_untill_event()
{
	struct s_state_info ret;
	pid_t pid = 0;
	int status = 0;

	/*struct sigaction act, old_act;
	act.sa_handler = alrm_handler;
	act.sa_flags = 0;

	sigemptyset(&act.sa_mask);
	sigaddset(&act.sa_mask, SIGCONT);
	if (sigaction(SIGALRM, &act, &old_act) == -1) 
	{
		perror("sigaction in wait_untill_event: ");
		ret.pid = 0;
		ret.retval = ERROR;
		goto exit;
	}



	struct itimerval s_it;	

	s_it.it_interval.tv_sec = TOUT;
	s_it.it_interval.tv_usec = 0;
	s_it.it_value.tv_sec = TOUT;
	s_it.it_value.tv_usec = 0;

	if (setitimer(ITIMER_REAL, &s_it, NULL) == -1)
	{
		perror("setitimer in wait_untill_event: ");
		ret.retval = ERROR;
		ret.pid = 0;
		goto timer;
	} */

	struct user_regs_struct regs;
	std:: cout << "WAIT\n";
	pid = waitpid(-1, &status, __WALL);

	if (pid == -1 && errno == EINTR) 
	{
		ret.retval = TIMEOUT;
		goto exit;
	}

	if (pid == -1 && errno == ECHILD) 
	{
		ret.retval = ALL_DEAD;
		goto exit;
	}

	if (pid == -1) 
	{
		ret.retval = ERROR;
		goto exit;
	}


	if (WIFEXITED(status)) // tracee unexpectively died
	{
		ret.pid = pid;
		ret.retval = DEAD;
		goto exit;
	}

	if (!WIFSTOPPED(status)) 
	{
		ret.retval = ERROR;
		return ret;
	}




	if (WSTOPSIG(status) == (SIGTRAP | 0x80))  // We are sure this is a syscall
	{
		if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
		{
			ret.retval = ERROR;
		}
		else 
			ret.retval = SYSCALL;

		ret.pid = pid;
		ret.registers = regs;

		goto exit;
	}
	if (status >> 8 == (SIGTRAP | PTRACE_EVENT_FORK << 8)) 
	{
		ret.retval = FORK;
		if (ptrace(PTRACE_GETEVENTMSG, pid, NULL, &ret.pid) == -1) 
		{
			ret.retval = ERROR;
			goto exit;
		}
		//printf("pid=%d ret.pid=%d\n", pid, ret.pid);
		if (pids_.find(s_pid_inf{pid, 0}) == pids_.end()) 
		{
			ret.pid = 0;
			long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK;
			if (ptrace(PTRACE_SETOPTIONS, pid, NULL, options) == -1 
				|| ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) 
			{
				ret.pid = ERROR;
			}
			
			goto exit;
		}
		if (ptrace(PTRACE_SYSCALL, pid, NULL, 0) == -1) 
		{
			ret.pid = ERROR;
		}
		goto exit;
	}

	if (status >> 8 == PTRACE_EVENT_STOP << 8) 
	{
		ret.retval = GROUPSTOP;
		ret.pid = pid;
		if (WSTOPSIG(status) == SIGSTOP || WSTOPSIG(status) == SIGTSTP 
			|| WSTOPSIG(status) == SIGTTIN || WSTOPSIG(status) == SIGTTOU) 
		{
			if (ptrace(PTRACE_LISTEN, pid, NULL, WSTOPSIG(status)) == -1) 
			{
				ret.retval = ERROR;
				goto exit;
			}
				
		}
		else {
			if (ptrace(PTRACE_CONT, pid, NULL, WSTOPSIG(status)) == -1) 
			{
				ret.retval = ERROR;
				goto exit;	
			}
		}
		goto exit;
	}

	// it is a signal

	siginfo_t sig_info;
	ptrace(PTRACE_GETSIGINFO, pid, NULL, &sig_info);
	ptrace(PTRACE_SYSCALL, pid, 0, sig_info.si_signo);
	ret.pid = pid;
	ret.signum = sig_info.si_signo;
	ret.retval = SIGNAL;

exit: 
	/*s_it.it_value.tv_sec = 0;
	s_it.it_value.tv_usec = 0;	
	setitimer(ITIMER_REAL, &s_it, NULL);
//timer:
	sigaction(SIGALRM, &old_act, NULL); */

	return ret;
}




void Tracer:: process_syscall(s_state_info event)
{
	switch(event.registers.orig_rax)
	{
		case event::OPEN:
		{
			char* path = alloc_and_get_arg_string(event.pid, event.registers.rdi);

			IPRINTF("%u: onEvent(%llu/%s, path='%s') start",
            	event.pid, event.registers.orig_rax,
            	event::toString(event.registers.orig_rax),
            	path);
			delete[](path);
			break;
		}
		case event::EXEC:
		{
			char* path = alloc_and_get_arg_string(event.pid, event.registers.rdi);

			IPRINTF("%u: onEvent(%llu/%s, path='%s') start",
            	event.pid, event.registers.orig_rax,
            	event::toString(event.registers.orig_rax),
            	path);
			delete[](path);
			break;	
		}
		case event::OPENAT:
		{
			char* path = alloc_and_get_arg_string(event.pid, event.registers.rsi);

			IPRINTF("%u: onEvent(%llu/%s, path='%s') start",
            	event.pid, event.registers.orig_rax,
            	event::toString(event.registers.orig_rax),
            	path);
			delete[](path);
			break;
		}
		default:
		{
			IPRINTF("%u: onEvent(%llu/%s) start",
            	event.pid, event.registers.orig_rax,
            	event::toString(event.registers.orig_rax));
			break;
		}
	}
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
		case SIGNAL:
		{
			IPRINTF("%d: Signal %d", event.pid, event.signum);
			break;
		}
		case TIMEOUT:
		{
			//printf("TO\n");
			break;
		}
		case ERROR:
		{
			break;
		}
		case DEAD:
		{
			IPRINTF("%d: dead", event.pid);
			{
    			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				pids_.erase(pids_.find(s_pid_inf{event.pid, 0}));
			}
			break;
		}
		case ALL_DEAD:
		{
			IPRINTF("All tracees are dead");
			sleep(2);
			break;
		}
		case GROUPSTOP:
		{
			IPRINTF("%u: onEvent groupstop", event.pid);
			break;
		}
		case FORK:
			if (event.pid == 0) 
			{
				break; // this should maybe restart infide wait_for_syscall()
			}
			IPRINTF("onEvent fork: child=%d", event.pid);

			{
    			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				pids_.insert(s_pid_inf{event.pid, 0});    			
			}

			break;
		case SYSCALL:
		{

			auto it = pids_.find(s_pid_inf{event.pid, 0});
			if (it == pids_.end()) 
			{
				IPRINTF("Unexpected pid: %d", event.pid);
				break;
			}

			if (event.registers.orig_rax == ABSOLUTELY_NOT_A_SYSCALL) 
			{
				event.registers.rax = -EPERM;
				ptrace(PTRACE_SETREGS, event.pid, NULL, event.registers);
			}

			/*if ((event.registers.orig_rax == SYSCALL_OPENAT)) 
			{
				if (openat_handler(set.arr[i].pid, &event.registers, set.arr[i].in_syscall) == -1)
					printf("%d: openat_handler failed\n", set.arr[i].pid);
			} 

			if ((event.registers.orig_rax == SYSCALL_OPEN)) 
			{
				if (open_handler(set.arr[i].pid, &event.registers, set.arr[i].in_syscall) == -1)
					printf("%d: open_handler failed\n", set.arr[i].pid);
			}*/

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


			{
    			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
				pids_.erase(it);
				pids_.insert(s_pid_inf{it->pid, in_syscall});
			}

			ptrace(PTRACE_SYSCALL, event.pid, NULL, NULL);
			break;
		}
		default:
		{
			printf("Strange event.retval=%d\n", event.retval);
		}
	}
}


void Tracer:: run_routine()
{
	int count = 0;
	while(1) 
	{
		{
			std:: cout << "ACTIVE\n";
    		std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
    		if (shutdown_)
    		{
    			std:: cout << "DEACTIVATION\n";
    			break;
    		}
		}

		if (!(count % UPDATE_LOOP)) 
		{
			std:: lock_guard<std::recursive_mutex> lock_guard(mutex_);
			update_pids();
		}
		count++;
		process_event(wait_untill_event());
	}
}




void Tracer:: run_proxy(void* self)
{
	static_cast<Tracer*>(self)->run_routine();
}

void Tracer:: update_pids()
{
	struct dirent* s_dir_ptr = NULL;
	char* ptr = NULL;
	DIR* dir_ptr = opendir("/proc");
	if (!dir_ptr)
		throw OPENDIR; 

	pid_t my_pid = getpid();
	
	while ((s_dir_ptr = readdir(dir_ptr))) 
	{
		struct s_pid_inf s_inf;
		s_inf.pid = strtol(s_dir_ptr->d_name, &ptr, 10);

		if (ptr && s_dir_ptr->d_name != ptr && *ptr == '\0' && s_inf.pid != my_pid) 
		{ 
			if (pids_.find(s_inf) == pids_.end() && check_pid(s_inf.pid))
			{
				if (attach_process(s_inf.pid)) 
				{
					std:: cout << "ATTACH FAILED " << s_inf.pid << std:: endl;
					perror("Attach:" );
					//return 0;
				}
				else 
				{
					std:: cout << s_inf.pid << std:: endl;
					s_inf.in_syscall = 0;
					pids_.insert(s_inf);
				}
			}
		}
	}

	closedir(dir_ptr);
}


void Tracer:: detach_all()
{
	for (auto it : pids_)
	{
		if (ptrace(PTRACE_DETACH, it.pid, NULL, NULL) == -1)
			perror("DETACH: ");
			std:: cout << it.pid << std:: endl;
	}
}




Tracer:: Tracer(/*event::Observer& driverEventObserver*/):
	//driverEventObserver_(driverEventObserver),
	thread_(std::thread(run_proxy, this))
{
	DPRINTF9("'Tracer' created");
} 

Tracer:: ~Tracer()
{
	DPRINTF9("stopping 'Tracer' thread");
	{
    	std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
    	shutdown_ = true;
    	kill(pids_.begin()->pid, SIGCHLD);
    	//detach_all();
	}

	
	thread_.join();
	DPRINTF9("destroying 'Tracer'");
}
