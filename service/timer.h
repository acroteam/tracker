// @brief class used to implement timeout during waitpid, which doesn't have its own implementation
#define DEFAULT_PERIOD 5 // seconds
#include <thread>
#include <mutex>

#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>


/* It is close to the functiont setitimer but send signal to the specific thread using tkill syscall*/


class PeriodicTimer
{
private:
	bool off_; 				// flags which timer thread will check every cycle to know
							//when it must stop its work

	unsigned int tid_; 		//thread id which will receive signals from this class
	unsigned int period_; 		// in seconds
	std::thread timer_thread_;
	mutable std::recursive_mutex mutex_;

	void run_timer();
	static void run_proxy(void* self);
public:
	PeriodicTimer(unsigned int tid, unsigned int period = DEFAULT_PERIOD);
	~PeriodicTimer();
};
#undef DEFAULT_PERIOD