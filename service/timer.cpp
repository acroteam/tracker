#include "timer.h"

void PeriodicTimer::run_proxy(void *self)
{
	static_cast<PeriodicTimer*>(self)->run_timer();
}

void PeriodicTimer::run_timer()
{
	while(1)
	{
		{
			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
			if (off_)
				return;
		}

		syscall(SYS_tkill, tid_, SIGALRM);
		sleep(period_);

	}
}



PeriodicTimer::PeriodicTimer(unsigned int tid, unsigned int period): 
off_(false),
tid_(tid),
period_(period),
timer_thread_(std::thread(run_proxy, this))
{}

PeriodicTimer::~PeriodicTimer()
{
	{
		std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
		off_ = true;
	}

	timer_thread_.join();
}

