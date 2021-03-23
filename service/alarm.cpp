#include "alarm.h"

void Alarm:: run_proxy(void *self)
{
	static_cast<Alarm*>(self)->run_routine();
}

void Alarm:: run_routine()
{
	while(1)
	{
		{
			std::lock_guard<std::recursive_mutex> lock_guard(mutex_);
			if (off_)
				return;
		}

		syscall(SYS_tkill, tid_, SIGALRM);
		sleep(7);

	}
}



Alarm:: Alarm(unsigned int tid):
off_(false),
tid_(tid),
routine_thread_(std:: thread(run_proxy, this))
{}

Alarm:: ~Alarm()
{
	{
		std:: lock_guard<std::recursive_mutex> lock_guard(mutex_);
		off_ = true;
	}

	routine_thread_.join();
}

