#include "app_common.h"
#include "util-lock.h"
#include "util-list.h"
#include "oscall.h"
#include "sockmgr.h"
#include "thread.h"
#include "dbsynctask.h"

static struct thread_master *dbsync_master;
static pthread_t g_thread_id;

static void* dbsync_run(void *args)
{
	struct thread_master *master = (struct thread_master *)args;
	struct thread t_thread;
	/* Prepare master thread. */
	while (thread_fetch(master, &t_thread)) {
		thread_call(&t_thread);
	}
	return NULL;
}
struct thread * dbsync_add_timer(int(*func) (struct thread *), void *arg, long interval)
{
	/* Add a timer */
	return thread_add_timer(dbsync_master, func, arg, interval);
}
int timer_fun(struct thread *t)
{
	thread_add_timer(dbsync_master, timer_fun, NULL, 10);
	return 0;
}
int gap_dbsync_init(void)
{
	dbsync_master = thread_master_create();

	thread_add_timer(dbsync_master, timer_fun, NULL, 0);
	int ret_val = pthread_create(&g_thread_id, NULL, dbsync_run, dbsync_master);
	if (ret_val != 0) {
		SCLogInfo("pthread_create error!");
		return -1;
	}

#ifdef USER_MEM_ALLOC
	ThreadMemInit("", g_thread_id);
#endif

	return 0;
}

void gap_dbsync_exit(void)
{
	pthread_cancel(g_thread_id);
	thread_master_free(dbsync_master);
}

