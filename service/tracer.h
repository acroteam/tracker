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





class Tracer 
{
private:
	std::set<s_pid_inf> pids_;
	//event::Observer& driverEventObserver_;
	mutable std:: recursive_mutex mutex_;
	std:: thread thread_;
	bool shutdown_ = false;

	void detach_all();
	void update_pids();
	void run_routine();
	s_state_info wait_untill_event();
	void process_event(s_state_info event);
	void process_syscall(s_state_info event);
	static void run_proxy(void* self);
public:

	Tracer(/*event::Observer& driverEventObserver*/);
	~Tracer();
};