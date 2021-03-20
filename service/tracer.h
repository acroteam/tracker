#pragma once

#include <set>
#include <thread>
#include <mutex>

#include <sys/user.h>
#include <unistd.h>

#include "event.h"

namespace tracer
{

enum class ProcessChangeStateReason
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

/* structire used to keep track of sequence of syscall entry and exit */
struct s_proc_inf 
{
	pid_t pid;
	int in_syscall;	
};

/* strucure used to describe changed state of traced process */
struct s_state_info
{
	pid_t pid; // process id of traced process
	struct user_regs_struct registers; 	// only when syscall is reason! registers of stopped process
	ProcessChangeStateReason reason; 	 
	int signum; // only when reason is signal! signal which 
};




class Tracer 
{
private:
	std::set<s_proc_inf> procs_inf_; 
	event::source::Observer& tracerEventObserver_;
	mutable std:: recursive_mutex mutex_;
	std:: thread routine_thread_;
	bool shutdown_ = false;
	int routine_tid_ = -1;

	void update_pids(); //may throw
	void run_routine(); //may throw
	//void run_watch(); //should not throw
	s_state_info wait_untill_event(); //may throw
	void process_event(s_state_info event); //may throw
	void process_syscall(s_state_info event); //may throw
	static void run_proxy(void* self);
public:

	Tracer(event::source::Observer& tracerEventObserver);
	~Tracer();
};
} // tracer