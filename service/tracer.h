#pragma once

#include <set>
#include <thread>
#include <mutex>

#include <sys/user.h>
#include <unistd.h>




struct s_pid_inf
{
	pid_t pid;
	int in_syscall;	
};

struct s_state_info
{
	pid_t pid;
	struct user_regs_struct registers;
	int retval;
	int signum;
};

enum class Thread_type
{
	ROUTINE,
	WATCH
};




class Tracer 
{
private:
	std::set<s_pid_inf> pids_;
	//event::Observer& driverEventObserver_;
	mutable std:: recursive_mutex mutex_;
	std:: thread routine_thread_, watch_thread_;
	bool shutdown_ = false;
	int routine_tid_ = -1;

	void update_pids(); //may throw
	void run_routine(); //may throw
	void run_watch(); //should not throw
	s_state_info wait_untill_event(); //may throw
	void process_event(s_state_info event); //may throw
	void process_syscall(s_state_info event); //may throw
	static void run_proxy(void* self, Thread_type type);
public:

	Tracer(/*event::Observer& driverEventObserver*/);
	~Tracer();
};