#include "app_common.h"

#include "util-debug.h"

#include <stdio.h>
#include <errno.h>
#include <linux/unistd.h>       /* for _syscallX macros/related stuff */
#include <linux/kernel.h>       /* for struct sysinfo */
#include <sys/sysinfo.h>

#include "threads.h"

/*Get system up time in second*/
long TimeGetUptime()
{
	struct sysinfo s_info;
	int error;
	error = sysinfo(&s_info);
	if (error != 0)
	{
		printf("code error = %d\n", error);
	}
	return s_info.uptime;
}

static struct timeval current_time = { 0, 0 };
//static SCMutex current_time_mutex = PTHREAD_MUTEX_INITIALIZER;
static SCSpinlock current_time_spinlock;
static char live = TRUE;

void TimeInit(void) {
	SCSpinInit(&current_time_spinlock, 0);
}

void TimeDeinit(void) {
	SCSpinDestroy(&current_time_spinlock);
}

void TimeModeSetLive(void)
{
	live = TRUE;
	SCLogDebug("live time mode enabled");
}

void TimeModeSetOffline(void)
{
	live = FALSE;
	SCLogDebug("offline time mode enabled");
}

void TimeSet(struct timeval *tv)
{
	if (live == TRUE)
		return;

	if (tv == NULL)
		return;

	SCSpinLock(&current_time_spinlock);
	current_time.tv_sec = tv->tv_sec;
	current_time.tv_usec = tv->tv_usec;

	SCLogDebug("time set to %" PRIuMAX " sec, %" PRIuMAX " usec",
		(uintmax_t)current_time.tv_sec, (uintmax_t)current_time.tv_usec);

	SCSpinUnlock(&current_time_spinlock);
}

/** \brief set the time to "gettimeofday" meant for testing */
void TimeSetToCurrentTime(void) {
	struct timeval tv;
	memset(&tv, 0x00, sizeof(tv));

	gettimeofday(&tv, NULL);

	TimeSet(&tv);
}

void TimeGet(struct timeval *tv)
{
	if (tv == NULL)
		return;

	if (live == TRUE) {
		gettimeofday(tv, NULL);
	}
	else {
		SCSpinLock(&current_time_spinlock);
		tv->tv_sec = current_time.tv_sec;
		tv->tv_usec = current_time.tv_usec;
		SCSpinUnlock(&current_time_spinlock);
	}

	SCLogDebug("time we got is %" PRIuMAX " sec, %" PRIuMAX " usec",
		(uintmax_t)tv->tv_sec, (uintmax_t)tv->tv_usec);
}

/** \brief increment the time in the engine
 *  \param tv_sec seconds to increment the time with */
void TimeSetIncrementTime(uint32_t tv_sec) {
	struct timeval tv;
	memset(&tv, 0x00, sizeof(tv));
	TimeGet(&tv);

	tv.tv_sec += tv_sec;

	TimeSet(&tv);
}


struct tm *SCLocalTime(time_t timep, struct tm *result)
{
	return localtime_r(&timep, result);
}

struct tm *SCUtcTime(time_t timep, struct tm *result)
{
	return gmtime_r(&timep, result);
}

