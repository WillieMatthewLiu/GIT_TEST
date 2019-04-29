#include "zebra.h"
#include "threads.h"
#include "util-mem.h"
#include "util-debug.h"


#define SC_LOG_SYNC_FREQ_UNIT               3600   /* day */
#define SC_LOG_MIN_SYN_FREQ                 1    /* hour */

int SCLogBufferRotateFlatModeCombineBackupLogData(SCLogBufFlatCtrl *ctrl,
	char *bak_flat_buffer_start, int bak_write_offset, int bak_write_loop, int bak_rotate_offset)
{
	int old_buf_1st_part_len = bak_write_offset;
	int old_buf_2nd_part_len = 0;
	if (bak_write_loop)
	{
		old_buf_2nd_part_len = SCLOGBUFFER_LEN - old_buf_1st_part_len;
	}
	int total_data_len = ctrl->write_offset + old_buf_1st_part_len +
		old_buf_2nd_part_len;

	int total_buf_len = SCLOGBUFFER_LEN;
	if (total_data_len <= SCLOGBUFFER_LEN)
	{
		total_buf_len = total_data_len;
	}
	else
	{
		total_data_len = SCLOGBUFFER_LEN;
	}

	// Step 1: move new data in current buffer
	// |--     Part A     --|-- Part B --|-- unused buffer --|
	// --> 
	// |-- unused buffer --|--     Part A     --|-- Part B --|
	// Assuming part A + part B are total data, part B are overlapped part if copying in
	// same buffer.
	// To avoid data overwritten while copying data , copy overlapped part firstly, 
	// then copy remaining part.
	// copy part B(overlapped part) to the end of buffer, then copy part A ahead of 
	// new part B. 

	int overlap_data = ctrl->write_offset * 2 - total_buf_len;
	if (overlap_data > 0)
	{
		overlap_data = overlap_data / 2 + 1;
	}
	else
	{
		overlap_data = 0;
	}
	// cp overlap data
	int copy_len = overlap_data;
	if (overlap_data)
	{
		memcpy(ctrl->flat_buffer_start + total_buf_len - copy_len,
			ctrl->flat_buffer_start + ctrl->write_offset - copy_len,
			copy_len);
		total_buf_len -= copy_len;

	}
	// cp remaining new data
	copy_len = ctrl->write_offset - overlap_data;
	memcpy(ctrl->flat_buffer_start + total_buf_len - copy_len,
		ctrl->flat_buffer_start, copy_len);
	total_buf_len -= copy_len;
	ctrl->rotate_offset = total_buf_len;

	// Step 2: copy 1st part(new part) in old buffer
	int start_offset = 0;
	copy_len = old_buf_1st_part_len;
	if (copy_len > total_buf_len)
	{
		copy_len = total_buf_len;
		start_offset = old_buf_1st_part_len - total_buf_len;
	}
	memcpy(ctrl->flat_buffer_start + total_buf_len - copy_len,
		bak_flat_buffer_start + start_offset, copy_len);
	total_buf_len -= copy_len;

	// Step 3: copy 2nd part (old part) in old buffer
	copy_len = old_buf_2nd_part_len;
	start_offset = bak_write_offset;
	if (copy_len > total_buf_len)
	{
		copy_len = total_buf_len;
		start_offset = bak_write_offset +
			old_buf_2nd_part_len - total_buf_len;
	}
	if (total_buf_len != copy_len)
	{
		printf("total_buf_len(%d) != copy_len(%d)\n",
			total_buf_len, copy_len);
	}
	if (copy_len)
	{
		memcpy(ctrl->flat_buffer_start,
			bak_flat_buffer_start + start_offset, copy_len);
	}

	ctrl->write_loop = 0;
	ctrl->rotate_offset = total_data_len - ctrl->write_offset;
	ctrl->write_offset = total_data_len;
	if (total_data_len == SCLOGBUFFER_LEN)
	{
		ctrl->write_offset = 0;
		ctrl->write_loop = 1;
	}

	return 0;
}

int SCLogBufferRotateFlatMode(SCLogBufCtrl *log_buf_ctrl, int iflock)
{
	int ret = 0;
	char *bak_flat_buffer_start = NULL;
	int bak_write_offset = 0;
	int bak_write_loop = 0;
	int bak_rotate_offset = 0;
	SCLogBufFlatCtrl *ctrl = &log_buf_ctrl->mode.flat;

	if (iflock)
	{
		SCMutexLock(&ctrl->flat_buffer_lock);
	}

	// switch main logging buffer
	bak_flat_buffer_start = ctrl->flat_buffer_start;
	ctrl->flat_buffer_start = ctrl->bak_flat_buffer_start;
	ctrl->bak_flat_buffer_start = bak_flat_buffer_start;

	bak_write_offset = ctrl->write_offset;
	ctrl->write_offset = 0;
	bak_write_loop = ctrl->write_loop;
	ctrl->write_loop = 0;
	bak_rotate_offset = ctrl->rotate_offset;
	ctrl->rotate_offset = -1;

	if (iflock)
	{
		SCMutexUnlock(&ctrl->flat_buffer_lock);
	}

	// rotate_offset points new data start, while write_offset points next place to
	// write new data.
	// The only chance that rotate_offset equals to write_offset is that
	// there is no new data after rotating curent buffer.
	// In the case write_offset reaches rotate_offset, rotate_offset will be 
	// set as -1 to indicate all new data.
	if (bak_rotate_offset == bak_write_offset)
	{
		return ret;
	}
	// If looping, write data stored before looping
	int start_offset = bak_write_offset;
	if (bak_write_loop)
	{
		// if write_offset doesn't reach rotate_offset, new data should starts from rotate_offset. 
		// |-----W->--R----|
		// if bak_rotate_offset is -1, the condition doesn't change.
		if (bak_write_offset < bak_rotate_offset)
		{
			start_offset = bak_rotate_offset;

		}
		{
			if (fwrite(bak_flat_buffer_start + start_offset,
				SCLOGBUFFER_LEN - start_offset, 1, zlog_default->fp) != 1) {
				printf("SCLogBufferRotateFlatMode: fwrite failed !\n");
			}
			fflush(zlog_default->fp);
		}

	}

	int data_len = bak_write_offset;
	start_offset = 0;
	// if write_offset doesn't reach rotate_offset (because bak_rotate_offset is still >= 0), 
	// and write_offset is ahead of rotate_offset, new data should starts from rotate_offset. 
	// |-----R---W->---|
	if ((bak_rotate_offset >= 0) && (bak_write_offset > bak_rotate_offset))
	{
		start_offset = bak_rotate_offset;
		data_len = bak_write_offset - bak_rotate_offset;
	}

	// Write data stored after looping 
	if (data_len)
	{
		{
			if (fwrite(bak_flat_buffer_start + start_offset,
				data_len, 1, zlog_default->fp) != 1) {
				printf("SCLogBufferRotateFlatMode: fwrite failed !\n");
			}
			fflush(zlog_default->fp);
		}
	}

#ifdef ENABLE_LOGBUF_TEST
	SCLogBufTestLogData(100);
#endif

	// keep more logging data in buffer so that user can view more logging via tty/web.
	if (iflock)
	{
		SCMutexLock(&ctrl->flat_buffer_lock);
		// write_loop indicates all loggings are new. no need switch buffer.
		if (!ctrl->write_loop)
		{
			if (ctrl->write_offset)
			{
				// combine old and new logging data into current buffer,
				SCLogBufferRotateFlatModeCombineBackupLogData(ctrl, bak_flat_buffer_start,
					bak_write_offset, bak_write_loop, bak_rotate_offset);
			}
			else
			{
				// if there is no new logging data in current buffer, switch back to old buffer.
				ctrl->bak_flat_buffer_start = ctrl->flat_buffer_start;
				ctrl->flat_buffer_start = bak_flat_buffer_start;
				ctrl->write_offset = bak_write_offset;
				ctrl->write_loop = bak_write_loop;
				ctrl->rotate_offset = ctrl->write_offset;
			}
		}
		SCMutexUnlock(&ctrl->flat_buffer_lock);
	}

	return ret;
}

int SCLogBufferRotateLinkListMode(SCLogBufCtrl *log_buf_ctrl, int iflock)
{
	int ret = 0;
	SCLogBuf *pos, *n;
	SCLogBufLinkListCtrl *ctrl = &log_buf_ctrl->mode.linklist;

	if (iflock)
		SCMutexLock(&ctrl->log_list_lock);

	list_for_each_entry_safe(pos, n, &ctrl->log_list, list)
	{
		fprintf(zlog_default->fp, "%s", pos->msg);
		list_del_init(&pos->list);
	}
	fflush(zlog_default->fp);
	ctrl->log_count = 0;
	ctrl->curr_pos = 0;

	if (iflock)
		SCMutexUnlock(&ctrl->log_list_lock);

	return ret;
}

int SCLogBufferRotate(SCLogBufCtrl *log_buf_ctrl, int iflock)
{
	if (SC_LOG_BUFFER_MODE_FLAT == log_buf_ctrl->buffer_mode)
	{
		return(SCLogBufferRotateFlatMode(log_buf_ctrl, iflock));
	}
	else if (SC_LOG_BUFFER_MODE_LINKLIST == log_buf_ctrl->buffer_mode)
	{
		return(SCLogBufferRotateLinkListMode(log_buf_ctrl, iflock));
	}
	return 0;
}

int SCLogBufIsFull(SCLogBufCtrl *log_buf_ctrl)
{
	if (SC_LOG_BUFFER_MODE_FLAT == log_buf_ctrl->buffer_mode)
	{
		if ((log_buf_ctrl->mode.flat.write_offset + SC_LOG_MAX_LOG_MSG_LEN > SCLOGBUFFER_LEN)
			|| log_buf_ctrl->mode.flat.write_loop)
			return 1;
	}
	else if (SC_LOG_BUFFER_MODE_LINKLIST == log_buf_ctrl->buffer_mode)
	{
		SCLogBufLinkListCtrl *linklist = NULL;
		linklist = &log_buf_ctrl->mode.linklist;
		if (linklist && (linklist->log_count >= linklist->max_log_count))
			return 1;
	}
	return 0;
}

void *SCLogBufHandle(void *arg)
{
	time_t prev, current;
	double diftime;
	SCLogBufCtrl *log_buf_ctrl = (SCLogBufCtrl *)arg;

	time(&prev);
	time(&current);
	for (;;)
	{
		time(&current);
		diftime = difftime(current, prev);
		if (log_buf_ctrl->flags ||
			(diftime - log_buf_ctrl->sync_freq*SC_LOG_SYNC_FREQ_UNIT > 0) ||
			(SCLogBufIsFull(log_buf_ctrl) && (diftime - SC_LOG_MIN_SYN_FREQ * SC_LOG_SYNC_FREQ_UNIT > 0)))
		{
			SCLogBufferRotate(log_buf_ctrl, 1);
			prev = current;
			log_buf_ctrl->flags = 0;
		}

		sleep(10);
	}
	return NULL;
}

int SCLogBufferInitFlatMode(struct zlog *zl)
{
	pthread_t pid;
	struct sched_param     param = { 0 };
	pthread_attr_t attr;
	int minpri;
	char *s;

	SCLogBufCtrl *log_buf_ctrl = SCMalloc(sizeof(SCLogBufCtrl));
	log_buf_ctrl->ptr = zl;

	log_buf_ctrl->sync_freq = 24;
	s = getenv(SC_LOG_ENV_LOG_SYNC_FREQ);
	if (s)
	{
		log_buf_ctrl->sync_freq = atoi(s);
	}

	SCLogBufFlatCtrl *ctrl = &log_buf_ctrl->mode.flat;

	if (SCMutexInit(&ctrl->flat_buffer_lock, NULL) != 0) {
		printf("error initializing flat_buffer_lock mutex");
		return -1;
	}
	ctrl->write_offset = 0;
	ctrl->write_loop = 0;
	ctrl->flat_buffer_start = SCMalloc(SCLOGBUFFER_LEN);
	ctrl->bak_flat_buffer_start = SCMalloc(SCLOGBUFFER_LEN);
	// lteng: -1 indicate all new.
	ctrl->rotate_offset = -1;


	pthread_attr_setschedpolicy(&attr, SCHED_RR);
	minpri = sched_get_priority_min(SCHED_RR);
	param.sched_priority = minpri;
	if (0 != pthread_attr_setschedparam(&attr, &param))
	{
		printf("pthread_attr_setschedparam failed.");
		return -1;
	}

	pthread_create(&pid, NULL, SCLogBufHandle, log_buf_ctrl);
#ifdef USER_MEM_ALLOC
	ThreadMemInit("", pid);
#endif
	return 0;
}

int SCLogBufferInitLinkListMode(struct zlog *zl)
{
	pthread_t pid;
	char *s;
	SCLogBufCtrl *log_buf_ctrl = SCMalloc(sizeof(SCLogBufCtrl));
	log_buf_ctrl->ptr = zl;

	log_buf_ctrl->sync_freq = 24;
	s = getenv(SC_LOG_ENV_LOG_SYNC_FREQ);
	if (s)
	{
		log_buf_ctrl->sync_freq = atoi(s);
	}

	SCLogBufLinkListCtrl *ctrl = &log_buf_ctrl->mode.linklist;
	memset(ctrl, 0, sizeof(SCLogBufLinkListCtrl));

	ctrl->buffer = (char *)SCMalloc(SCLOGBUFFER_LEN);
	if (NULL == ctrl->buffer)
		return -1;

	SCMutexInit(&ctrl->log_list_lock, NULL);

	INIT_LIST_HEAD(&ctrl->log_list);
	ctrl->log_count = 0;
	ctrl->max_log_count = 10000;
	s = getenv(SC_LOG_ENV_LOG_MAX_LOG_COUNT);
	if (s)
	{
		ctrl->max_log_count = atoi(s);
	}

	pthread_create(&pid, NULL, SCLogBufHandle, log_buf_ctrl);
#ifdef USER_MEM_ALLOC
	ThreadMemInit("", pid);
#endif

	return 0;
}


int SCLogBufferInit(struct zlog *zl)
{
	int mode;
	const char *s = getenv(SC_LOG_ENV_LOG_BUFFER_MODE);
	if (!s)
		return 0;

	mode = atoi(s);

	if (SC_LOG_BUFFER_MODE_FLAT == mode)
	{
		return(SCLogBufferInitFlatMode(zl));
	}
	else if (SC_LOG_BUFFER_MODE_LINKLIST == mode)
	{
		return(SCLogBufferInitLinkListMode(zl));
	}
	return -1;
}

