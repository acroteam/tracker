#include <thread>
#include <mutex>

#include <unistd.h>
#include <signal.h>
#include <sys/syscall.h>


class Alarm
{
private:
	bool off_;
	unsigned int tid_;
	std:: thread routine_thread_;
	mutable std:: recursive_mutex mutex_;

	void run_routine();
	static void run_proxy(void* self);
public:
	Alarm(unsigned int tid);
	~Alarm();
};