
#ifndef __UTIL_DEBUG_H__
#define __UTIL_DEBUG_H__

#include <stdio.h>
#include <stdint.h>
#include "log.h"
#include "util-list.h"

#define SC_LOG_ENV_LOG_BUFFER_MODE  "SC_LOG_BUFFER_MODE"
#define SC_LOG_ENV_LOG_MAX_LOG_COUNT "SC_LOG_MAX_LOG_COUNT"
#define SC_LOG_ENV_LOG_SYNC_FREQ    "SC_LOG_SYNC_FREQ"
/* The maximum length of the log message */
#define SC_LOG_MAX_LOG_MSG_LEN 2048

#define SCLOGBUFFER_LEN (1024*1024)  /* 10M bytes: 10*1024*1024 */
/**
 * log buffer mode
 */
typedef enum {
	SC_LOG_BUFFER_MODE_DISABLE = 0,
	SC_LOG_BUFFER_MODE_LINKLIST,
	SC_LOG_BUFFER_MODE_FLAT,
	SC_LOG_BUFFER_MODE_MAX,
} SCLogBufferMode;

typedef struct {
	struct list_head log_list;
	unsigned int log_count;
	unsigned int max_log_count;
	unsigned int curr_pos;
	char *buffer;
	SCMutex log_list_lock;
}SCLogBufLinkListCtrl;

typedef struct {
	SCMutex flat_buffer_lock;
	int write_offset; // the start postion to be written.
	int write_loop;
	char* flat_buffer_start;
	char* bak_flat_buffer_start;
	// -1 indicate all new: initlal value; or write_offset reaches rotate_offset.
	// >=0 indicate data between rotate_offset and write_offset are new.
	int rotate_offset;
}SCLogBufFlatCtrl;

typedef struct {
	/* if buffer_mode is set, all log will save to buffer, and rotate by other thread */
	int buffer_mode;
	int sync_freq; /* hours */
	int flags;
	union
	{
		SCLogBufLinkListCtrl linklist;
		SCLogBufFlatCtrl flat;
	}mode;
	void *ptr;
} SCLogBufCtrl;
typedef struct _SCLogBuf {
	struct list_head list;
	int log_level;
	int msg_len;
	char msg[0];
}SCLogBuf;


#define SCLogEmerg zlog_emerg
#define SCLogAlert zlog_alert
#define SCLogCritical zlog_critical
#define SCLogError zlog_err
#define SCLogWarning zlog_warn
#define SCLogInfo  zlog_info
#define SCLogNotice zlog_notice
#define SCLogDebug zlog_debug

#define SCLogLoadConfig(d, f) \
    do{\
        char *p, *progname;\
         progname = ((p = strrchr (argv[0], '/')) ? ++p : argv[0]);\
    zlog_default = openzlog (progname, ZLOG_DEFAULT, \
			   LOG_CONS|LOG_NDELAY|LOG_PID, LOG_DAEMON); \
    }while(0)

#endif /* __UTIL_DEBUG_H__ */
