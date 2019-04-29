/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_file_sync.h
Author         : liuzongquan(000932)
Version        : V1.0
Date           : 2017.3.24
Description    : dirtory synchronization
Other          : null
Function List  : Main function list, each record should include the function name and function brief description
Modify History : 1. date:
				 2. version:
				 3. author:
				 4. id:
				 5. modify:
********************************************************************************/
#ifndef __PARSER_SYNC_H__
#define __PARSER_SYNC_H__
#include "zebra.h"
#include "list.h"

#define INOTIFY_EVENT_NUM           12

#define FILE_SYNC_CONFIG_MAX        15

#define SHARE_SYNC_COMM_LEN         32

#define SHARE_SYNC_COMMAND_LEN      256

#define SHARE_EVENT_CACHE_SIZE      8192

#define SHARE_SUFFIX_STRING         "~"

#define SHARE_DIFF_FILE_NAME        "diff.txt"

#define SHARE_DELETE_FILE_NAME      "delete.txt"

#define SHARE_INCLUDE_FILE_NAME     "include.txt"

#define SHARE_EXCLUDE_FILE_NAME     "exclude.txt"

#define SHARE_TMP_DST_EXIST_NAME    "tmpDstExist.txt"

#define SHARE_OLD_DST_EXIST_NAME    "oldDstExist.txt"

#define SHARE_NEW_DST_EXIST_NAME    "newDstExist.txt"

#define SHARE_SYNC_BINARY           "/usr/bin/rsync"

#define SHARE_SYNC_CONFIG_PATH      "/etc/rsyncd.conf"

#define SHARE_SYNC_BASE_DIR         "/var/volatile/tmp/"

#define SHARE_SYNC_DEFAULT_CONFIG   "####################################################\n" \
                                    "# /etc/rsyncd.conf\n#\n" \
                                    "# Minimal configuration file for rsync daemon\n" \
                                    "# See rsync(1) and rsyncd.conf(5) man pages for help\n#\n" \
                                    "# This file is required by rsync --daemon\n" \
                                    "####################################################\n\n" \
                                    "[global]\nmax connections = 65535\nlog file = /var/log/rsync.log\ntimeout = 300\n\n"

/* common config */
#define SYNC_CONFIG_TASK_NAME       "name"
#define SYNC_CONFIG_SWITCH          "state"
#define SYNC_CONFIG_DIRECTION       "direction"

/* inner | outer config */
#define SYNC_CONFIG_INNER_NAME      "inner"
#define SYNC_CONFIG_OUTER_NAME      "outer"
#define SYNC_CONFIG_DIR             "dir"
#define SYNC_CONFIG_IP              "ip"
#define SYNC_CONFIG_USER            "user"
#define SYNC_CONFIG_PASSWD          "passwd"

/* extend */
#define SYNC_CONFIG_EXTEND_NAME     "extend"
#define SYNC_CONFIG_DETECT_DST      "detect_dst"
#define SYNC_CONFIG_DEL_SRC_FILE    "del_src"
#define SYNC_CONFIG_DEL_SRC_DIR     "del_src_dir"
#define SYNC_CONFIG_AV_NAME         "av"
#define SYNC_CONFIG_CHANGE_NAME     "changename"
#define SYNC_CONFIG_SYNCDEL         "syncdel"
#define SYNC_CONFIG_TASKTYPE        "tasktype"
#define SYNC_CONFIG_TIMEVAL         "timeval"
#define SYNC_CONFIG_SYNCTYPE        "synctype"
#define SYNC_CONFIG_FILESUFFIX      "filesuffix"

/* sync config switch-value */
typedef enum SHARE_SYNC_STATUS_E
{
	SYNC_CONFIG_INVALID = 0,                /**< invalid */
	SYNC_CONFIG_VALID,                      /**< valid   */
	SHARE_SYNC_STATUS_BUTT
} SHARE_SYNC_STATUS;

typedef enum SHARE_SYNC_DIRECTION_E
{
	OUT_TO_IN = 1,          /**< out -> in */
	IN_TO_OUT,
	OUT_AND_IN,
	SYNC_DIRECTION_BUTT
} SHARE_SYNC_DIRECTION;

typedef enum SHARE_PLAN_TYPE_E
{
	IMMEDIATELY_SYNC = 1,
	TIMING_SYNC,
	PLAN_TYPE_BUTT
} SHARE_PLAN_TYPE;

typedef enum SHARE_SYNC_TYPE_E
{
	ALL_SYNC = 1,
	INCLUDE_SYNC,
	EXCLUDE_SYNC,
	SYNC_TYPE_BUTT
} SHARE_SYNC_TYPE;

/*
* Error codes returned by rsync.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*/
typedef enum SHARE_COMMAND_EXIT_CODE_E
{
	RERR_OK = 0,    /* success */
	RERR_SYNTAX,                /* syntax or usage error */
	RERR_PROTOCOL,              /* protocol incompatibility */
	RERR_FILESELECT,            /* errors selecting input/output files, dirs */
	RERR_UNSUPPORTED,           /* requested action not supported */
	RERR_STARTCLIENT,           /* error starting client-server protocol */

	RERR_SOCKETIO = 10,   /* error in socket IO */
	RERR_FILEIO,                /* error in file IO */
	RERR_STREAMIO,              /* error in rsync protocol data stream */
	RERR_MESSAGEIO,             /* errors with program diagnostics */
	RERR_IPC,                   /* error in IPC code */
	RERR_CRASHED,               /* sibling crashed */
	RERR_TERMINATED,            /* sibling terminated abnormally */

	RERR_SIGNAL1 = 19,   /* status returned when sent SIGUSR1 */
	RERR_SIGNAL,                /* status returned when sent SIGINT, SIGTERM, SIGHUP */
	RERR_WAITCHILD,             /* some error returned by waitpid() */
	RERR_MALLOC,                /* error allocating core memory buffers */
	RERR_PARTIAL,               /* partial transfer */
	RERR_VANISHED,              /* file(s) vanished on sender side */
	RERR_DEL_LIMIT,             /* skipped some deletes due to --max-delete */

	RERR_TIMEOUT = 30,   /* timeout in data send/receive */
	RERR_CONTIMEOUT = 35,   /* timeout waiting for daemon connection */

	/* Although it doesn't seem to be specified anywhere,
	* and we could use this to give a better explanation if the remote
	* command is not found.
	*/
	RERR_CMD_FAILED = 124,  /* if the command exited with status 255 */
	RERR_CMD_KILLED,            /* if the command is killed by a signal */
	RERR_CMD_RUN,               /* if the command cannot be run */
	RERR_CMD_NOTFOUND,          /* if the command is not found */
	RERR_CMD_BUTT
} SHARE_COMMAND_EXIT_CODE;

typedef struct SHARE_FOLDER_PARA_S
{
	char *folderName;
	char *ip;
	char *username;
	char *password;
} SHARE_FOLDER_PARA;

typedef struct SHARE_EXTEND_PARA_S
{
	char isDetectDst;
	char isDelSrcFile;
	char isDelSrcDir;
	char isVirusScan;
	char isChangeName;
	char isDeleteSync;
	SHARE_PLAN_TYPE planType;
	unsigned int intervalTime;
	SHARE_SYNC_TYPE syncType;
	char *syncTypeBuff;
} SHARE_EXTEND_PARA;

typedef struct SHARE_UNCHANGE_INFO_S
{
	int taskNameLen;
	int outFolderNameLen;
	int inFolderNameLen;
	int extendTypeBuffLen;
} SHARE_UNCHANGE_INFO;

typedef struct SHARE_SYNC_PARA_S
{
	struct list_head node;
	long syncSize;
	int isFirst;
	int inotifyId;
	int isSyncSuccess;
	int configState;
	SHARE_SYNC_DIRECTION direction;
	SHARE_FOLDER_PARA outFolder;
	SHARE_FOLDER_PARA inFolder;
	SHARE_EXTEND_PARA extendPara;
	SHARE_UNCHANGE_INFO unchangeInfo;
	pthread_mutex_t timerLock;
	char *taskName;
	struct json_object *json;
	struct thread *timer;
} SHARE_SYNC_PARA;

typedef struct INOTIFY_THREAD_INFO_S
{
	pthread_t id;
	unsigned int isUsed;
	unsigned int modifyCount;
	int fd;
	char *path;
} INOTIFY_THREAD_INFO;

typedef struct INOTIFY_CLEAENUP_ARGS_S
{
	int inotifyId;
	int fd;
	int wd;
	char *buff;
} INOTIFY_CLEAENUP_ARGS;

typedef struct FSYNC_UNCHANGE_INFO_S
{
	int baseDirLen;
	int diffFileLen;
	int deleteFileLen;
	int includeFileLen;
	int excludeFileLen;
	int tmpDstFileLen;
	int oldDstFileLen;
	int newDstFileLen;
} FSYNC_UNCHANGE_INFO;

void freeConfigObj(SHARE_SYNC_PARA *pconfig);

int syncTimerRepeat(SHARE_SYNC_PARA *pconfig);

int setOneConfigEnable(const char *taskName);

int setOneConfigDisable(const char *taskName);

int delOneConfig(const char *taskName);

int addOneConfig(SHARE_SYNC_PARA *pconfig);

#endif
