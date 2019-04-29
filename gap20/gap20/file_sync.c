/********************************************************************************

		   Copyright (C), 2016, 2017, Kuang Network Technology Co., Ltd.
*********************************************************************************
Filename       : parser_sync.c
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
#include <pthread.h>
#include <glib.h>
#include <sys/inotify.h>
#include "app_common.h"
#include "vector.h"
#include "thread.h"
#include "json-c.h"
#include "db_mysql.h"
#include "cmd_common.h"
#include "parser_common.h"
#include "rsync.h"
#include "file_sync.h"

/* whether the file cache to the gap */
static int g_isCache = PARSER_BFALSE;

/* timer thread */
static pthread_t g_syncThread;
static struct thread g_syncTimerthread;
static struct thread_master *g_syncMaster = NULL;

/* not change config info */
static FSYNC_UNCHANGE_INFO *g_fsyncUnchangeInfo = NULL;

/* share config information */
pthread_rwlock_t g_fileSyncLock;
struct list_head g_fileSyncConfig;

pthread_mutex_t g_inotifyLock;
static INOTIFY_THREAD_INFO *g_inotifyThreadPool = NULL;

/* command exit string */
static const char *g_commandExitString[RERR_CMD_BUTT] =
{
	[RERR_OK] = "success",
	[RERR_SYNTAX] = "syntax or usage error",
	[RERR_PROTOCOL] = "protocol incompatibility",
	[RERR_FILESELECT] = "errors selecting input/output files, dirs",
	[RERR_UNSUPPORTED] = "requested action not supported",
	[RERR_STARTCLIENT] = "error starting client-server protocol",

	[RERR_SOCKETIO] = "error in socket IO",
	[RERR_FILEIO] = "error in file IO",
	[RERR_STREAMIO] = "error in rsync protocol data stream",
	[RERR_MESSAGEIO] = "errors with program diagnostics",
	[RERR_IPC] = "error in IPC code",
	[RERR_CRASHED] = "sibling crashed",
	[RERR_TERMINATED] = "sibling terminated abnormally",

	[RERR_SIGNAL1] = "status returned when sent SIGUSR1",
	[RERR_SIGNAL] = "status returned when sent SIGINT, SIGTERM, SIGHUP",
	[RERR_WAITCHILD] = "some error returned by waitpid()",
	[RERR_MALLOC] = "error allocating core memory buffers",
	[RERR_PARTIAL] = "partial transfer",
	[RERR_VANISHED] = "file(s) vanished on sender side",
	[RERR_DEL_LIMIT] = "skipped some deletes due to --max-delete",

	[RERR_TIMEOUT] = "timeout in data send/receive",
	[RERR_CONTIMEOUT] = "timeout waiting for daemon connection",

	[RERR_CMD_FAILED] = "if the command exited with status 255",
	[RERR_CMD_KILLED] = "if the command is killed by a signal",
	[RERR_CMD_RUN] = "if the command cannot be run",
	[RERR_CMD_NOTFOUND] = "if the command is not found"
};

/************************************************************
*Function    : isAlreadyMount
*Action      : check dir mount
*Input       : command  command
*Output      : null
*Return      : PARSER_BTRUE    OK
			   PARSER_BFALSE   ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.5
*Instruction : null
************************************************************/
static int isAlreadyMount(char *command)
{
	int ret;
	char buff[SHARE_SYNC_COMM_LEN];

	ret = cmd_system_getout(command, buff, SHARE_SYNC_COMM_LEN);
	if (-1 == ret)
	{
		SCLogError("[%s:%d]cmd_system_getout error, ret(%d), command(%s), buff:%s",
			__func__, __LINE__, ret, command, buff);
		return PARSER_BFALSE;
	}

	if (!strncmp(buff, "1", 1))
	{
		return PARSER_BTRUE;
	}

	return PARSER_BFALSE;
}

/************************************************************
*Function    : excuteCommand
*Action      : excute command
*Input       : command          command
			   isPrintReason    print reason
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int excuteCommand(char *command, int isPrintReason)
{
	int exitNo;

	exitNo = cmd_system_novty(command);
	if (-1 == exitNo)
	{
		SCLogError("[%s:%d]cmd_system_novty error, command(%s)!", __func__, __LINE__, command);
		return PARSER_ERROR;
	}

	switch (exitNo)
	{
	case RERR_OK:
	case RERR_PARTIAL:
	{
		return PARSER_OK;
	}

	case RERR_SYNTAX:
	case RERR_PROTOCOL:
	case RERR_FILESELECT:
	case RERR_UNSUPPORTED:
	case RERR_STARTCLIENT:
	case RERR_SOCKETIO:
	case RERR_FILEIO:
	case RERR_STREAMIO:
	case RERR_MESSAGEIO:
	case RERR_IPC:
	case RERR_CRASHED:
	case RERR_TERMINATED:
	case RERR_SIGNAL1:
	case RERR_SIGNAL:
	case RERR_WAITCHILD:
	case RERR_MALLOC:
	case RERR_VANISHED:
	case RERR_DEL_LIMIT:
	case RERR_TIMEOUT:
	case RERR_CONTIMEOUT:
	case RERR_CMD_FAILED:
	case RERR_CMD_KILLED:
	case RERR_CMD_RUN:
	case RERR_CMD_NOTFOUND:
	{
		if (isPrintReason)
		{
			SCLogError("[%s:%d]%s, exitNo(%d), command(%s)!",
				__func__, __LINE__, g_commandExitString[exitNo], exitNo, command);
		}
		return PARSER_ERROR;
	}

	default:
	{
		if (isPrintReason)
		{
			SCLogError("[%s:%d]unknow exitNo(%d), command(%s)!", __func__, __LINE__, exitNo, command);
		}
		return PARSER_ERROR;
	}
	}
}

/************************************************************
*Function    : replaceChar
*Action      : replace char
*Input       : typeBuff buff
			   sc       source char
			   dc       dest char
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.7
*Instruction : null
************************************************************/
static void replaceChar(char *typeBuff, char sc, char dc)
{
	if (NULL == typeBuff)
	{
		return;
	}

	while (*typeBuff)
	{
		if (sc == *typeBuff)
		{
			*typeBuff = dc;
		}
		typeBuff++;
	}
}

/************************************************************
*Function    : getTotalSize
*Action      : get total size(format: 2,615,361)
*Input       : totalSizeString
*Output      : null
*Return      : totalSize
*Author      : liuzongquan(000932)
*Date        : 2017.4.12
*Instruction : null
************************************************************/
static long getTotalSize(char *totalSizeString)
{
	long value;
	long totalSize;
	char *outPtr = NULL;
	char *ptemp = NULL;

	totalSize = 0;
	ptemp = strtok_r(totalSizeString, ",", &outPtr);
	while (ptemp)
	{
		value = atol(ptemp);
		totalSize = totalSize * 1000 + value;
		ptemp = strtok_r(NULL, ",", &outPtr);
	}

	return totalSize;
}

/************************************************************
*Function    : handleLocalFile
*Action      : handle local file after sync
*Input       : buff   sync file list
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.5.3
*Instruction : null
************************************************************/
static void handleLocalFile(char *buff, SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder)
{
	int len;
	int flag;
	int cmdLen;
	char *ptemp = NULL;
	char *outptr = NULL;
	char *fileBuf = NULL;
	char *commond = NULL;

	if (NULL == buff)
	{
		return;
	}

	len = strlen(buff) + 1;
	fileBuf = SCMalloc(len);
	if (NULL == fileBuf)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, len);
		return;
	}
	strcpy(fileBuf, buff);

	cmdLen = g_fsyncUnchangeInfo->baseDirLen
		+ pconfig->unchangeInfo.taskNameLen
		+ pconfig->unchangeInfo.inFolderNameLen
		+ pconfig->unchangeInfo.outFolderNameLen
		+ SHARE_SYNC_COMM_LEN + len;
	commond = SCMalloc(cmdLen);
	if (NULL == commond)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, len);
		SCFree(fileBuf);
		return;
	}
	snprintf(commond, cmdLen, "cd %s%s/%s%s; rm -rf ",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName, g_isCache ? "1" : "");

	flag = PARSER_BFALSE;
	ptemp = strtok_r(fileBuf, "\n", &outptr);
	while (ptemp)
	{
		if (0 != memcmp("./", ptemp, 3))
		{
			len = strlen(ptemp);
			if ('/' == *(ptemp + len - 1))
			{
				if (pconfig->extendPara.isDelSrcDir)
				{
					strcat(commond, ptemp);
					strcat(commond, " ");
					if (!flag)
					{
						flag = PARSER_BTRUE;
					}
				}
			}
			else
			{
				if (pconfig->extendPara.isDelSrcFile)
				{
					strcat(commond, ptemp);
					strcat(commond, " ");
					if (!flag)
					{
						flag = PARSER_BTRUE;
					}
				}
			}
		}
		ptemp = strtok_r(NULL, "\n", &outptr);
	}

	if (flag)
	{
		(void)excuteCommand(commond, PARSER_BFALSE);
	}

	SCFree(commond);
	commond = NULL;
	SCFree(fileBuf);
	fileBuf = NULL;
	return;
}

/************************************************************
*Function    : wirteDbFileList
*Action      : write file list to db
*Input       : pconfig      configuration data
			   buff         buff
			   len          buff len
			   ipString     ip info
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.11
*Instruction : null
************************************************************/
static void wirteDbFileList(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder, char *buff, int len, char *ipString)
{
	long newSize;
	long oldSize;
	long syncSize;
	int contentLen;
	char totalSizeString[SHARE_SYNC_COMM_LEN];
	char *pstring = NULL;
	char *content = NULL;

	/* get total size */
	pstring = strstr(buff, "total size is");
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]not fine total size, buff(%s)", __func__, __LINE__, buff);
		return;
	}

	sscanf(pstring, "%*s%*s%*s%s%*s", totalSizeString);
	newSize = getTotalSize(totalSizeString);
	oldSize = pconfig->syncSize;
	pconfig->syncSize = newSize;
	//SCLogInfo("[%s:%d]old size(%ld), new size(%ld)", __func__, __LINE__, oldSize, newSize);
	if (oldSize >= newSize)
	{
		syncSize = oldSize - newSize;
	}
	else
	{
		syncSize = newSize - oldSize;
	}
	//SCLogInfo("[%s:%d]sync size is :%ld", __func__, __LINE__, syncSize);

	/* get file list */
	contentLen = strlen("sending incremental file list\n");
	if (strncmp(buff, "sending incremental file list\n", contentLen))
	{
		SCLogError("[%s:%d]invalid start, buff(%s)", __func__, __LINE__, buff);
		return;
	}
	buff += contentLen;
	if ('\n' == *buff)
	{
		//SCLogInfo("[%s:%d]share dirtory not change.", __func__, __LINE__);
		return;
	}

	pstring = strstr(buff, "\n\n");
	if (NULL == pstring)
	{
		SCLogError("[%s:%d]invalid end, buff(%s)", __func__, __LINE__, buff);
		return;
	}
	*pstring = '\0';

	if (!strcmp(buff, "./"))
	{
		//SCLogInfo("[%s:%d]share dirtory not change.", __func__, __LINE__);
		return;
	}

	/* handle local file after sync */
	if (!g_isCache)
	{
		handleLocalFile(buff, pconfig, localFolder);
	}

	replaceChar(buff, '\n', '?');

	if (ipString)
	{
		contentLen = len + strlen(ipString);
	}
	else
	{
		contentLen = len;
	}

	content = (char *)SCMalloc(contentLen);
	if (NULL == content)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, contentLen);
		return;
	}

	snprintf(content, contentLen, "%s(同步文件内容长度:%ld 文件列表:%s)", ipString, syncSize, buff);
	SCLogInfo("[%s:%d]content:%s", __func__, __LINE__, content);
	INSERT_SYS_LOG("文件同步", l_info, content);

	SCFree(content);
	content = NULL;
	return;
}

/************************************************************
*Function    : writeDbLog
*Action      : write db log
*Input       : pconfig          configuration data
			   localFolder      local folder
			   remoteFolder     remote folder
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.10
*Instruction : null
************************************************************/
static void writeDbLog(SHARE_SYNC_PARA *pconfig,
	SHARE_FOLDER_PARA *localFolder,
	SHARE_FOLDER_PARA *remoteFolder,
	char *command, char *buf, int len)
{
	int stringLen;
	char *ipString = NULL;

	stringLen = 0;
	if ((NULL != localFolder->ip) && (NULL != remoteFolder->ip)
		&& (NULL != localFolder->folderName) && (NULL != remoteFolder->folderName))
	{
		stringLen = strlen(localFolder->ip) + strlen(remoteFolder->ip)
			+ strlen(localFolder->folderName) + strlen(remoteFolder->folderName);
		if (0 < stringLen)
		{
			ipString = (char *)SCMalloc(stringLen + 5);
			if (ipString)
			{
				snprintf(ipString, stringLen + 5, "%s:%s->%s:%s",
					localFolder->ip, localFolder->folderName,
					remoteFolder->ip, remoteFolder->folderName);
			}
		}
	}

	if ((0 == len) || (NULL == strstr(buf, "total size is")))
	{
		if (pconfig->isSyncSuccess)
		{
			/* write db false info */
			SCLogError("[%s:%d]rsync failed, len(%d), buff(%s), command(%s)", __func__, __LINE__, len, buf, command);

			INSERT_SYS_LOG("文件同步", l_error, ipString ? ipString : "");
			pconfig->isSyncSuccess = PARSER_BFALSE;
		}
		return;
	}

	/* write db success info: file list */
	if (!(pconfig->isSyncSuccess))
	{
		SCLogInfo("[%s:%d]rsync success, task(%s)", __func__, __LINE__, pconfig->taskName);
		pconfig->isSyncSuccess = PARSER_BTRUE;
	}

	wirteDbFileList(pconfig, localFolder, buf, len, ipString);

	if (ipString)
	{
		SCFree(ipString);
		ipString = NULL;
	}

	return;
}

/************************************************************
*Function    : writeDiffFiles
*Action      : write diff file list to diff.txt
*Input       : pconfig          configuration data
			   localFolder      local folder
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int writeDiffFiles(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder, char *buff, int count)
{
	int len;
	FILE *fp = NULL;
	char *endPos = NULL;
	char *startPos = NULL;
	char *path = NULL;

	if (NULL == buff)
	{
		SCLogError("[%s:%d]invalid para, buff is null, task(%s)", __func__, __LINE__, pconfig->taskName);
		return PARSER_ERROR;
	}

	startPos = strstr(buff, "sending incremental file list\n");
	if (NULL == startPos)
	{
		SCLogError("[%s:%d]invalid start, buff(%s), task(%s)", __func__, __LINE__, buff, pconfig->taskName);
		return PARSER_ERROR;
	}
	len = strlen("sending incremental file list\n");
	startPos += len;

	endPos = strstr(startPos, "\n\n");
	if (NULL == endPos)
	{
		SCLogError("[%s:%d]invalid end, buff(%s), task(%s)", __func__, __LINE__, buff, pconfig->taskName);
		return PARSER_ERROR;
	}

	len = g_fsyncUnchangeInfo->baseDirLen
		+ pconfig->unchangeInfo.taskNameLen
		+ g_fsyncUnchangeInfo->diffFileLen
		+ 2;
	path = (char *)SCMalloc(len);
	if (NULL == path)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, len);
		return PARSER_ERROR;
	}

	if (0 > snprintf(path, len, "%s%s/%s", SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_DIFF_FILE_NAME))
	{
		SCLogError("[%s:%d]snprintf failed, task(%s)!", __func__, __LINE__, pconfig->taskName);
		SCFree(path);
		return PARSER_ERROR;
	}

	len = (int)(endPos - startPos);
	fp = fopen(path, "w");
	if (NULL == fp)
	{
		SCLogError("[%s:%d]fopen failed, path(%s), task(%s)", __func__, __LINE__, path, pconfig->taskName);
		SCFree(path);
		return PARSER_ERROR;
	}

	fwrite(startPos, 1, len, fp);

	if (0 != fclose(fp))
	{
		SCLogError("[%s:%d]fclose failed, path(%s), task(%s)", __func__, __LINE__, path, pconfig->taskName);
		SCFree(path);
		return PARSER_ERROR;
	}

	SCFree(path);
	return PARSER_OK;
}

/************************************************************
*Function    : excuteCommandGetout
*Action      : exucte command and get buff
*Input       : pconfig          configuration data
			   localFolder      local folder
			   remoteFolder     remote folder
			   command  command
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.6
*Instruction : null
************************************************************/
static int excuteCommandGetout(SHARE_SYNC_PARA *pconfig,
	SHARE_FOLDER_PARA *localFolder,
	SHARE_FOLDER_PARA *remoteFolder,
	char *command)
{
	int count;
	char *buff = NULL;

	buff = (char *)SCMalloc(SHARE_EVENT_CACHE_SIZE);
	if (NULL == buff)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, SHARE_EVENT_CACHE_SIZE);
		return PARSER_ERROR;
	}

	count = cmd_system_getout(command, buff, SHARE_EVENT_CACHE_SIZE);
	if (0 > count)
	{
		SCLogError("[%s:%d]cmd_system_getout error, ret(%d), command(%s)", __func__, __LINE__, count, command);
		SCFree(buff);
		buff = NULL;
		return PARSER_ERROR;
	}
	buff[count] = '\0';

	if (0 == count)
	{
		SCLogWarning("[%s:%d]remote is preparing, task(%s)", __func__, __LINE__, pconfig->taskName);
		SCFree(buff);
		buff = NULL;
		return PARSER_ERROR;
	}

	if (g_isCache)
	{
		if (PARSER_OK != writeDiffFiles(pconfig, localFolder, buff, count))
		{
			SCLogError("[%s:%d]write diff file list error, command(%s)", __func__, __LINE__, command);
			SCFree(buff);
			buff = NULL;
			return PARSER_ERROR;
		}
	}

	//SCLogInfo("[%s:%d]cmd_system_getout success, len(%d), buff(%s), command(%s)",
	//             __func__, __LINE__, count, buff, command);
	writeDbLog(pconfig, localFolder, remoteFolder, command, buff, count);

	SCFree(buff);
	buff = NULL;

	pconfig->isFirst = PARSER_BFALSE;

	return PARSER_OK;
}

/************************************************************
*Function    : configIncludeExclude
*Action      : config include/excude file
*Input       : pconfig          configuration data
			   fileName     file name
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.7
*Instruction : null
************************************************************/
static void configIncludeExclude(SHARE_SYNC_PARA *pconfig, const char *fileName)
{
	int cmdLen;
	char *command = NULL;

	cmdLen = pconfig->unchangeInfo.extendTypeBuffLen
		+ g_fsyncUnchangeInfo->baseDirLen
		+ pconfig->unchangeInfo.taskNameLen
		+ g_fsyncUnchangeInfo->includeFileLen
		+ g_fsyncUnchangeInfo->excludeFileLen
		+ SHARE_SYNC_COMM_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return;
	}

	snprintf(command, cmdLen, "%s%s/%s", SHARE_SYNC_BASE_DIR, pconfig->taskName, fileName);
	if (0 != access(command, 0))
	{
		replaceChar(pconfig->extendPara.syncTypeBuff, '|', '\n');
		snprintf(command, cmdLen, "echo \"%s\" > %s%s/%s",
			pconfig->extendPara.syncTypeBuff, SHARE_SYNC_BASE_DIR, pconfig->taskName, fileName);
		(void)excuteCommand(command, PARSER_BFALSE);
	}

	SCFree(command);
	return;
}

/************************************************************
*Function    : clientConfig
*Action      : client configuration
*Input       : pconfig          configuration data
			   clientFolderPara client param
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int clientConfig(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *clientFolderPara)
{
	int cmdLen;
	char *command = NULL;

	cmdLen = (SHARE_SYNC_COMM_LEN * 3)
		+ ((pconfig->unchangeInfo.outFolderNameLen + pconfig->unchangeInfo.inFolderNameLen) * 2)
		+ g_fsyncUnchangeInfo->baseDirLen
		+ (pconfig->unchangeInfo.taskNameLen * 3)
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	/* create dirtory */
	snprintf(command, cmdLen, "%s%s/%s", SHARE_SYNC_BASE_DIR, pconfig->taskName, clientFolderPara->folderName);
	if (0 != access(command, 0))
	{
		snprintf(command, cmdLen, "mkdir -p %s%s/%s",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, clientFolderPara->folderName);
		(void)excuteCommand(command, PARSER_BFALSE);
	}

	/* check mount ornot */
	snprintf(command, cmdLen, "mount |grep \"%s%s/%s\" |wc -l",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, clientFolderPara->folderName);
	if (!isAlreadyMount(command))
	{
		/* mount */
		snprintf(command, cmdLen,
			"mount -t cifs -o username=%s,password=%s,rw,sync,dir_mode=0644,file_mode=0644,sec=ntlm //%s/%s %s%s/%s/",
			clientFolderPara->username,
			clientFolderPara->password,
			clientFolderPara->ip,
			clientFolderPara->folderName,
			SHARE_SYNC_BASE_DIR,
			pconfig->taskName,
			clientFolderPara->folderName);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			SCFree(command);
			return PARSER_ERROR;
		}
		SCLogInfo("[%s:%d]mount success, command(%s)", __func__, __LINE__, command);
	}

	/* set password(password) file */
	snprintf(command, cmdLen, "%s%s/%s.rsync",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	if (0 != access(command, 0))
	{
		/* add password file */
		snprintf(command, cmdLen, "echo \"%s\" > %s%s/%s.rsync",
			pconfig->taskName, SHARE_SYNC_BASE_DIR,
			pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);

		/* set 600 */
		snprintf(command, cmdLen, "chmod 600 %s%s/%s.rsync",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);
	}

	/* set include.txt and exclude.txt */
	if (INCLUDE_SYNC == pconfig->extendPara.syncType)
	{
		configIncludeExclude(pconfig, SHARE_INCLUDE_FILE_NAME);
	}
	else if (EXCLUDE_SYNC == pconfig->extendPara.syncType)
	{
		configIncludeExclude(pconfig, SHARE_EXCLUDE_FILE_NAME);
	}

	SCFree(command);
	return PARSER_OK;
}

static int getRsyncModuleParaSpace(SHARE_SYNC_PARA *pconfig, struct rsync_module_parameters **module)
{
	int len;
	struct rsync_module_parameters *pmodule = NULL;

	len = sizeof(struct rsync_module_parameters);
	pmodule = (struct rsync_module_parameters *)SCMalloc(len);
	if (NULL == pmodule)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, len);
		return PARSER_ERROR;
	}

	memset(pmodule, 0, len);
	pmodule->name = pconfig->taskName;
	len = g_fsyncUnchangeInfo->baseDirLen + pconfig->unchangeInfo.taskNameLen + 1;
	pmodule->path = (char *)SCMalloc(len);
	if (NULL == pmodule->path)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, len);
		SCFree(pmodule);
		return PARSER_ERROR;
	}
	snprintf(pmodule->path, len, "%s%s", SHARE_SYNC_BASE_DIR, pconfig->taskName);
	pmodule->read_only = 0;
	pmodule->list = 1;
	pmodule->uid = "root";
	pmodule->gid = "root";
	pmodule->auth_users = pconfig->taskName;
	len = g_fsyncUnchangeInfo->baseDirLen + (pconfig->unchangeInfo.taskNameLen * 2) + 10;
	pmodule->secrets_file = (char *)SCMalloc(len);
	if (NULL == pmodule->secrets_file)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, len);
		SCFree(pmodule->path);
		SCFree(pmodule);
		return PARSER_ERROR;
	}
	snprintf(pmodule->secrets_file, len, "%s%s/%s.secrets", SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	pmodule->fake_super = PARSER_INVALUE8;
	pmodule->forward_lookup = PARSER_INVALUE8;
	pmodule->ignore_errors = PARSER_INVALUE8;
	pmodule->ignore_nonreadable = PARSER_INVALUE8;
	pmodule->munge_symlinks = PARSER_INVALUE8;
	pmodule->numeric_ids = PARSER_INVALUE8;
	pmodule->reverse_lookup = PARSER_INVALUE8;
	pmodule->strict_modes = PARSER_INVALUE8;
	pmodule->transfer_logging = PARSER_INVALUE8;
	pmodule->use_chroot = PARSER_INVALUE8;
	pmodule->write_only = PARSER_INVALUE8;

	*module = pmodule;
	return PARSER_OK;
}

static void putRsyncModuleParaSpace(struct rsync_module_parameters *module)
{
	if (NULL == module)
	{
		return;
	}

	if (module->secrets_file)
	{
		SCFree(module->secrets_file);
	}

	if (module->path)
	{
		SCFree(module->path);
	}

	SCFree(module);
	return;
}

/************************************************************
*Function    : ruleConfig
*Action      : rule config
*Input       : pconfig configuration data
*Output      : isChange          config change ornot
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.7
*Instruction : null
************************************************************/
static void ruleConfig(SHARE_SYNC_PARA *pconfig, int *isChange)
{
	int ret;
	int cmdLen;
	char buff[SHARE_SYNC_COMM_LEN];
	char *command = NULL;
	struct rsync_module_parameters *module = NULL;

	cmdLen = (pconfig->unchangeInfo.taskNameLen * 5)
		+ (g_fsyncUnchangeInfo->baseDirLen * 2)
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return;
	}

	snprintf(command, cmdLen, "grep \"\\[%s\\]\" %s |wc -l", pconfig->taskName, SHARE_SYNC_CONFIG_PATH);
	ret = cmd_system_getout(command, buff, SHARE_SYNC_COMM_LEN);
	if (-1 == ret)
	{
		SCLogError("[%s:%d]cmd_system_getout error, ret(%d), command(%s), buff:%s", __func__, __LINE__, ret, command, buff);
		SCFree(command);
		return;
	}

	if (!strncmp(buff, "0", 1))
	{
		/* create rule */
		if (PARSER_OK != getRsyncModuleParaSpace(pconfig, &module))
		{
			SCFree(command);
			return;
		}

		if (PARSER_OK != rsync_write_module(SHARE_SYNC_CONFIG_PATH, module))
		{
			SCLogError("[%s:%d]rsync_write_module error, task name(%s)", __func__, __LINE__, pconfig->taskName);
			SCFree(command);
			return;
		}

		putRsyncModuleParaSpace(module);

		*isChange = PARSER_BTRUE;
	}

	SCFree(command);
	return;
}

/************************************************************
*Function    : serverConfig
*Action      : server configuration
*Input       : pconfig configuration data
			   serverFolderPara server param
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int serverConfig(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *serverFolderPara)
{
	int cmdLen;
	int isChange;
	char *command = NULL;

	cmdLen = (SHARE_SYNC_COMM_LEN * 3)
		+ ((pconfig->unchangeInfo.outFolderNameLen + pconfig->unchangeInfo.inFolderNameLen) * 2)
		+ g_fsyncUnchangeInfo->baseDirLen
		+ (pconfig->unchangeInfo.taskNameLen * 4)
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	/* change flag */
	isChange = PARSER_BFALSE;

	/* create dirtory */
	snprintf(command, cmdLen, "%s%s/%s", SHARE_SYNC_BASE_DIR, pconfig->taskName, serverFolderPara->folderName);
	if (0 != access(command, 0))
	{
		snprintf(command, cmdLen, "mkdir -p %s%s/%s",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, serverFolderPara->folderName);
		(void)excuteCommand(command, PARSER_BFALSE);
		isChange = PARSER_BTRUE;
	}

	/* mount */
	snprintf(command, cmdLen, "mount |grep \"%s%s/%s\" |wc -l",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, serverFolderPara->folderName);
	if (!isAlreadyMount(command))
	{
		snprintf(command, cmdLen,
			"mount -t cifs -o username=%s,password=%s,rw,sync,dir_mode=0644,file_mode=0644,sec=ntlm //%s/%s %s%s/%s/",
			serverFolderPara->username, serverFolderPara->password,
			serverFolderPara->ip, serverFolderPara->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, serverFolderPara->folderName);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			SCFree(command);
			return PARSER_ERROR;
		}
		isChange = PARSER_BTRUE;
		SCLogInfo("[%s:%d]mount success, command(%s)", __func__, __LINE__, command);
	}

	/* config rule */
	ruleConfig(pconfig, &isChange);

	/* set password(username:password) */
	snprintf(command, cmdLen, "%s%s/%s.secrets", SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	if (0 != access(command, 0))
	{
		/* set password */
		snprintf(command, cmdLen, "echo \"%s:%s\" > %s%s/%s.secrets",
			pconfig->taskName, pconfig->taskName, SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);

		/* set 600 */
		snprintf(command, cmdLen, "chmod 600 %s%s/%s.secrets",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);
		isChange = PARSER_BTRUE;
	}

	if (isChange)
	{
		/* reboot service */
		SCLogInfo("[%s:%d]reboot rsync, enable taskName(%s).", __func__, __LINE__, pconfig->taskName);
		(void)excuteCommand("kill -9 `pidof rsync` >/dev/null 2>&1", PARSER_BFALSE);
	}

	SCFree(command);
	return PARSER_OK;
}

/************************************************************
*Function    : configSync
*Action      : config sync
*Input       : pconfig configuration data
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int configSync(SHARE_SYNC_PARA *pconfig)
{
	int ret;

	if (RUN_AS_OUTER())
	{
		ret = clientConfig(pconfig, &(pconfig->outFolder));
		if (PARSER_OK == ret)
		{
			ret = serverConfig(pconfig, &(pconfig->outFolder));
		}
	}
	else
	{
		ret = clientConfig(pconfig, &(pconfig->inFolder));
		if (PARSER_OK == ret)
		{
			ret = serverConfig(pconfig, &(pconfig->inFolder));
		}
	}

	return ret;
}

/************************************************************
*Function    : checkDstExcludeFiles
*Action      : check dest exclude files
*Input       : command
			   cmdLen           command length
			   pconfig          configuration data
			   localFolder      local folder
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.5.19
*Instruction : null
************************************************************/
static int checkDstExcludeFiles(char *command, int cmdLen,
	SHARE_SYNC_PARA *pconfig,
	SHARE_FOLDER_PARA *localFolder,
	SHARE_FOLDER_PARA *remoteFolder,
	char *remoteIp)
{
	if ((0 == pconfig->extendPara.isDeleteSync) || (INCLUDE_SYNC == pconfig->extendPara.syncType))
	{
		snprintf(command, cmdLen, "echo > %s%s/%s",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_OLD_DST_EXIST_NAME);
		(void)excuteCommand(command, PARSER_BFALSE);
		return PARSER_OK;
	}

	if (ALL_SYNC == pconfig->extendPara.syncType)
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s && rsync -a%svn -R --delete ./ --timeout=100 " \
			"%s@%s::%s/%s --password-file=%s%s/%s.rsync " \
			"|grep \"^deleting \" |awk 'BEGIN{FS=\" \"}{print $2}END{}' > %s%s/%s",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName,
			(pconfig->isFirst) ? SHARE_OLD_DST_EXIST_NAME : SHARE_NEW_DST_EXIST_NAME);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			return PARSER_ERROR;
		}
	}
	else
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s && rsync -a%svn -R --delete ./ " \
			"--exclude-from=\"%s%s/%s\" --timeout=100 " \
			"%s@%s::%s/%s --password-file=%s%s/%s.rsync " \
			"|grep \"^deleting \" |awk 'BEGIN{FS=\" \"}{print $2}END{}' > %s%s/%s",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_EXCLUDE_FILE_NAME,
			pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName,
			(pconfig->isFirst) ? SHARE_OLD_DST_EXIST_NAME : SHARE_NEW_DST_EXIST_NAME);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			return PARSER_ERROR;
		}

	}

	if (!(pconfig->isFirst))
	{
		snprintf(command, cmdLen, "grep -wf %s%s/%s %s%s/%s > %s%s/%s",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_NEW_DST_EXIST_NAME,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_OLD_DST_EXIST_NAME,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_TMP_DST_EXIST_NAME);
		(void)excuteCommand(command, PARSER_BFALSE);

		snprintf(command, cmdLen, "mv %s%s/%s %s%s/%s -f",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_TMP_DST_EXIST_NAME,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_OLD_DST_EXIST_NAME);
		(void)excuteCommand(command, PARSER_BFALSE);
	}

	return PARSER_OK;
}

/************************************************************
*Function    : syncDirtory
*Action      : sync dirtory
*Input       : pconfig          configuration data
			   localFolder      local folder
			   remoteFolder     remote folder
			   remoteIp         remote ip
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static void syncDirtory(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder, SHARE_FOLDER_PARA *remoteFolder, char *remoteIp)
{
	int cmdLen;
	char *command = NULL;

	cmdLen = (g_fsyncUnchangeInfo->baseDirLen * 4)
		+ (pconfig->unchangeInfo.taskNameLen * 7)
		+ pconfig->unchangeInfo.inFolderNameLen
		+ pconfig->unchangeInfo.outFolderNameLen
		+ g_fsyncUnchangeInfo->includeFileLen
		+ g_fsyncUnchangeInfo->excludeFileLen
		+ g_fsyncUnchangeInfo->tmpDstFileLen
		+ g_fsyncUnchangeInfo->oldDstFileLen
		+ g_fsyncUnchangeInfo->newDstFileLen
		+ SHARE_SYNC_COMM_LEN
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return;
	}

	if (PARSER_OK != checkDstExcludeFiles(command, cmdLen, pconfig, localFolder, remoteFolder, remoteIp))
	{
		SCFree(command);
		return;
	}

	if (ALL_SYNC == pconfig->extendPara.syncType)
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s && rsync -a%sv%s -R%s ./ --exclude-from=\"%s%s/%s\" --suffix=%s --timeout=100 " \
			"%s@%s::%s/%s --password-file=%s%s/%s.rsync 2>/dev/null",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			(pconfig->extendPara.isChangeName) ? "b" : "",
			(pconfig->extendPara.isDeleteSync) ? " --delete" : "",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_OLD_DST_EXIST_NAME,
			SHARE_SUFFIX_STRING, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	}
	else if (INCLUDE_SYNC == pconfig->extendPara.syncType)
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s && rsync -a%sv%s -R%s ./ " \
			"--include-from=\"%s%s/%s\" --exclude=\"*\" --suffix=%s --timeout=100 " \
			"%s@%s::%s/%s --password-file=%s%s/%s.rsync 2>/dev/null",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			(pconfig->extendPara.isChangeName) ? "b" : "",
			(pconfig->extendPara.isDeleteSync) ? " --delete" : "",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_INCLUDE_FILE_NAME,
			SHARE_SUFFIX_STRING, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	}
	else
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s && rsync -a%sv%s -R%s ./ --exclude-from=\"%s%s/%s\" " \
			"--exclude-from=\"%s%s/%s\" --suffix=%s --timeout=100 " \
			"%s@%s::%s/%s --password-file=%s%s/%s.rsync 2>/dev/null",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			(pconfig->extendPara.isChangeName) ? "b" : "",
			(pconfig->extendPara.isDeleteSync) ? " --delete" : "",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_OLD_DST_EXIST_NAME,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_EXCLUDE_FILE_NAME,
			SHARE_SUFFIX_STRING, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	}

	(void)excuteCommandGetout(pconfig, localFolder, remoteFolder, command);

	SCFree(command);
	return;
}

/************************************************************
*Function    : getInotifyId
*Action      : get free inotify id
*Input       : null
*Output      : null
*Return      : -1:not find free id  index:free id
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int getInotifyId(void)
{
	int index;

	pthread_mutex_lock(&g_inotifyLock);
	for (index = 0; index < FILE_SYNC_CONFIG_MAX; index++)
	{
		if (!g_inotifyThreadPool[index].isUsed)
		{
			g_inotifyThreadPool[index].isUsed = PARSER_BTRUE;
			pthread_mutex_unlock(&g_inotifyLock);
			return index;
		}
	}
	pthread_mutex_unlock(&g_inotifyLock);

	return -1;
}

/************************************************************
*Function    : putInotifyId
*Action      : free inotify id
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static void putInotifyId(int notifyId)
{
	if ((FILE_SYNC_CONFIG_MAX <= notifyId) || (0 > notifyId))
	{
		SCLogError("[%s:%d]invalid notify id(%d), [0, %d]!", __func__, __LINE__, notifyId, FILE_SYNC_CONFIG_MAX - 1);
		return;
	}

	pthread_mutex_lock(&g_inotifyLock);
	g_inotifyThreadPool[notifyId].isUsed = PARSER_BFALSE;
	pthread_mutex_unlock(&g_inotifyLock);
}

/************************************************************
*Function    : freeConfigObj
*Action      : free config object
*Input       : pconfig configuration data
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.10
*Instruction : null
************************************************************/
void freeConfigObj(SHARE_SYNC_PARA *pconfig)
{
	if ((0 <= pconfig->inotifyId) && (FILE_SYNC_CONFIG_MAX > pconfig->inotifyId))
	{
		if (g_inotifyThreadPool[pconfig->inotifyId].isUsed)
		{
			if (0 != pthread_cancel(g_inotifyThreadPool[pconfig->inotifyId].id))
			{
				SCLogError("[%s:%d]pthread_cancel failed, task(%s)!", __func__, __LINE__, pconfig->taskName);
			}
		}

		if (g_inotifyThreadPool[pconfig->inotifyId].path)
		{
			SCFree(g_inotifyThreadPool[pconfig->inotifyId].path);
			g_inotifyThreadPool[pconfig->inotifyId].path = NULL;
		}

		putInotifyId(pconfig->inotifyId);
		pconfig->inotifyId = -1;
	}

	if (pconfig->taskName)
	{
		SCFree(pconfig->taskName);
	}
	if (pconfig->inFolder.folderName)
	{
		SCFree(pconfig->inFolder.folderName);
	}
	if (pconfig->inFolder.ip)
	{
		SCFree(pconfig->inFolder.ip);
	}
	if (pconfig->inFolder.username)
	{
		SCFree(pconfig->inFolder.username);
	}
	if (pconfig->inFolder.password)
	{
		SCFree(pconfig->inFolder.password);
	}
	if (pconfig->outFolder.folderName)
	{
		SCFree(pconfig->outFolder.folderName);
	}
	if (pconfig->outFolder.ip)
	{
		SCFree(pconfig->outFolder.ip);
	}
	if (pconfig->outFolder.username)
	{
		SCFree(pconfig->outFolder.username);
	}
	if (pconfig->outFolder.password)
	{
		SCFree(pconfig->outFolder.password);
	}
	if (pconfig->extendPara.syncTypeBuff)
	{
		SCFree(pconfig->extendPara.syncTypeBuff);
	}
	if (pconfig->json)
	{
		json_object_put(pconfig->json);
	}
	SCFree(pconfig);
	return;
}

/************************************************************
*Function    : freeConfigNode
*Action      : pconfig configuration data
*Input       : null
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.3.31
*Instruction : null
************************************************************/
static void freeConfigNode(SHARE_SYNC_PARA *pconfig)
{
	pthread_rwlock_wrlock(&g_fileSyncLock);
	list_del(&pconfig->node);
	pthread_rwlock_unlock(&g_fileSyncLock);
	freeConfigObj(pconfig);
	return;
}

/************************************************************
*Function    : clientCacheConfig
*Action      : client cache configuration
*Input       : pconfig          configuration data
			   clientFolderPara client param
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int clientCacheConfig(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *clientFolderPara)
{
	int index;
	int cmdLen;
	char *command = NULL;

	cmdLen = (SHARE_SYNC_COMM_LEN * 3)
		+ ((pconfig->unchangeInfo.outFolderNameLen + pconfig->unchangeInfo.inFolderNameLen) * 2)
		+ g_fsyncUnchangeInfo->baseDirLen
		+ (pconfig->unchangeInfo.taskNameLen * 3)
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	/* create dirtory */
	for (index = 1; index <= 3; index++)
	{
		snprintf(command, cmdLen, "%s%s/%s%d", SHARE_SYNC_BASE_DIR, pconfig->taskName, clientFolderPara->folderName, index);
		if (0 != access(command, 0))
		{
			snprintf(command, cmdLen, "mkdir -p %s%s/%s%d",
				SHARE_SYNC_BASE_DIR, pconfig->taskName,
				clientFolderPara->folderName, index);
			(void)excuteCommand(command, PARSER_BFALSE);
		}
	}

	/* check mount ornot */
	snprintf(command, cmdLen, "mount |grep \"%s%s/%s1\" |wc -l",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, clientFolderPara->folderName);
	if (!isAlreadyMount(command))
	{
		/* mount */
		snprintf(command, cmdLen,
			"mount -t cifs -o username=%s,password=%s,rw,sync,dir_mode=0644,file_mode=0644,sec=ntlm //%s/%s %s%s/%s1/",
			clientFolderPara->username,
			clientFolderPara->password,
			clientFolderPara->ip,
			clientFolderPara->folderName,
			SHARE_SYNC_BASE_DIR,
			pconfig->taskName,
			clientFolderPara->folderName);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			SCFree(command);
			return PARSER_ERROR;
		}
		SCLogInfo("[%s:%d]mount success, command(%s)", __func__, __LINE__, command);
	}

	/* set password(password) file */
	snprintf(command, cmdLen, "%s%s/%s.rsync", SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	if (0 != access(command, 0))
	{
		/* add password file */
		snprintf(command, cmdLen, "echo \"%s\" > %s%s/%s.rsync",
			pconfig->taskName, SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);

		/* set 600 */
		snprintf(command, cmdLen, "chmod 600 %s%s/%s.rsync",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);
	}

	/* set include.txt and exclude.txt */
	if (INCLUDE_SYNC == pconfig->extendPara.syncType)
	{
		configIncludeExclude(pconfig, SHARE_INCLUDE_FILE_NAME);
	}
	else if (EXCLUDE_SYNC == pconfig->extendPara.syncType)
	{
		configIncludeExclude(pconfig, SHARE_EXCLUDE_FILE_NAME);
	}

	SCFree(command);
	return PARSER_OK;
}

/************************************************************
*Function    : ruleCacheConfig
*Action      : rule cache config
*Input       : pconfig configuration data
*Output      : isChange         config change flag
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.7
*Instruction : null
************************************************************/
static void ruleCacheConfig(SHARE_SYNC_PARA *pconfig, int *isChange)
{
	int ret;
	int cmdLen;
	char buff[SHARE_SYNC_COMM_LEN];
	char *command = NULL;
	struct rsync_module_parameters *module = NULL;

	cmdLen = (pconfig->unchangeInfo.taskNameLen * 5)
		+ (g_fsyncUnchangeInfo->baseDirLen * 2)
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return;
	}

	snprintf(command, cmdLen, "grep \"\\[%s\\]\" %s |wc -l", pconfig->taskName, SHARE_SYNC_CONFIG_PATH);
	ret = cmd_system_getout(command, buff, SHARE_SYNC_COMM_LEN);
	if (-1 == ret)
	{
		SCLogError("[%s:%d]cmd_system_getout error, ret(%d), command(%s), buff:%s", __func__, __LINE__, ret, command, buff);
		SCFree(command);
		return;
	}

	if (!strncmp(buff, "0", 1))
	{
		/* create rule */
		if (PARSER_OK != getRsyncModuleParaSpace(pconfig, &module))
		{
			SCFree(command);
			return;
		}

		if (PARSER_OK != rsync_write_module(SHARE_SYNC_CONFIG_PATH, module))
		{
			SCLogError("[%s:%d]rsync_write_module error, task name(%s)", __func__, __LINE__, pconfig->taskName);
			SCFree(command);
			return;
		}

		putRsyncModuleParaSpace(module);

		*isChange = PARSER_BTRUE;
	}

	SCFree(command);
	return;
}

/************************************************************
*Function    : serverCacheConfig
*Action      : server cache configuration
*Input       : pconfig configuration data
			   serverFolderPara server param
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int serverCacheConfig(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *serverFolderPara)
{
	int index;
	int cmdLen;
	int isChange;
	char *command = NULL;

	cmdLen = (SHARE_SYNC_COMM_LEN * 3)
		+ ((pconfig->unchangeInfo.outFolderNameLen + pconfig->unchangeInfo.inFolderNameLen) * 2)
		+ g_fsyncUnchangeInfo->baseDirLen
		+ (pconfig->unchangeInfo.taskNameLen * 4)
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	/* change flag */
	isChange = PARSER_BFALSE;

	/* create dirtory */
	for (index = 1; index <= 3; index++)
	{
		snprintf(command, cmdLen, "%s%s/%s%d", SHARE_SYNC_BASE_DIR, pconfig->taskName, serverFolderPara->folderName, index);
		if (0 != access(command, 0))
		{
			snprintf(command, cmdLen, "mkdir -p %s%s/%s%d",
				SHARE_SYNC_BASE_DIR, pconfig->taskName,
				serverFolderPara->folderName, index);
			(void)excuteCommand(command, PARSER_BFALSE);
			isChange = PARSER_BTRUE;
		}
	}

	/* mount */
	snprintf(command, cmdLen, "mount |grep \"%s%s/%s1\" |wc -l",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, serverFolderPara->folderName);
	if (!isAlreadyMount(command))
	{
		snprintf(command, cmdLen,
			"mount -t cifs -o username=%s,password=%s,rw,sync,dir_mode=0644,file_mode=0644,sec=ntlm //%s/%s %s%s/%s1/",
			serverFolderPara->username, serverFolderPara->password,
			serverFolderPara->ip, serverFolderPara->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, serverFolderPara->folderName);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			SCFree(command);
			return PARSER_ERROR;
		}
		isChange = PARSER_BTRUE;
		SCLogInfo("[%s:%d]mount success, command(%s)", __func__, __LINE__, command);
	}

	/* config rule */
	ruleCacheConfig(pconfig, &isChange);

	/* set password(username:password) */
	snprintf(command, cmdLen, "%s%s/%s.secrets", SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	if (0 != access(command, 0))
	{
		/* set password */
		snprintf(command, cmdLen, "echo \"%s:%s\" > %s%s/%s.secrets",
			pconfig->taskName, pconfig->taskName, SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);

		/* set 600 */
		snprintf(command, cmdLen, "chmod 600 %s%s/%s.secrets",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		(void)excuteCommand(command, PARSER_BFALSE);
		isChange = PARSER_BTRUE;
	}

	if (isChange)
	{
		/* reboot service */
		SCLogInfo("[%s:%d]reboot rsync, enable taskName(%s).", __func__, __LINE__, pconfig->taskName);
		(void)excuteCommand("kill -9 `pidof rsync` >/dev/null 2>&1", PARSER_BFALSE);
	}

	SCFree(command);
	return PARSER_OK;
}

/************************************************************
*Function    : inotifyCleanupHandler
*Action      : inotify thread exit handle
*Input       : arg
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static void inotifyCleanupHandler(void *arg)
{
	INOTIFY_CLEAENUP_ARGS *inotifyCleanupArgs = NULL;

	if (NULL == arg)
	{
		return;
	}

	inotifyCleanupArgs = (INOTIFY_CLEAENUP_ARGS *)arg;
	if (0 > inotify_rm_watch(inotifyCleanupArgs->fd, inotifyCleanupArgs->wd))
	{
		SCLogError("[%s:%d]inotify_rm_watch failed, path(%s)!",
			__func__, __LINE__, g_inotifyThreadPool[inotifyCleanupArgs->inotifyId].path);
	}

	close(inotifyCleanupArgs->fd);

	if (inotifyCleanupArgs->buff)
	{
		SCFree(inotifyCleanupArgs->buff);
	}

	SCFree(inotifyCleanupArgs);
}

/************************************************************
*Function    : runFileSyncInotify
*Action      : inotify thread running
*Input       : argv
*Output      : null
*Return      : NULL
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
void *runFileSyncInotify(void *argv)
{
	int fd;
	int wd;
	int len;
	int nread;
	int inotifyId;
	unsigned char index;
	unsigned char size;
	char *buff = NULL;
	struct inotify_event *event = NULL;
	INOTIFY_CLEAENUP_ARGS *inotifyCleanupArgs = NULL;

	inotifyId = *(int *)argv;

	if (0 != pthread_detach(pthread_self()))
	{
		SCLogError("[%s:%d]pthread_detach failed, path(%s)!",
			__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
		g_inotifyThreadPool[inotifyId].fd = -1;
		return NULL;
	}

	if (0 != pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL))
	{
		SCLogError("[%s:%d]pthread_setcancelstate failed, path(%s)!",
			__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
		g_inotifyThreadPool[inotifyId].fd = -1;
		return NULL;
	}

	if (0 != pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL))
	{
		SCLogError("[%s:%d]pthread_setcanceltype failed, path(%s)!",
			__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
		g_inotifyThreadPool[inotifyId].fd = -1;
		return NULL;
	}

	fd = inotify_init();
	if (fd < 0)
	{
		SCLogError("[%s:%d]inotify_init failed, path(%s)!",
			__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
		g_inotifyThreadPool[inotifyId].fd = -1;
		return NULL;
	}

	wd = inotify_add_watch(fd, g_inotifyThreadPool[inotifyId].path, IN_ALL_EVENTS);
	if (wd < 0)
	{
		SCLogError("[%s:%d]inotify_add_watch failed, path(%s)!",
			__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
		g_inotifyThreadPool[inotifyId].fd = -1;
		close(fd);
		return NULL;
	}

	size = sizeof(struct inotify_event);
	buff = (char *)SCMalloc(SHARE_EVENT_CACHE_SIZE);
	if (NULL == buff)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)!", __func__, __LINE__, size);
		g_inotifyThreadPool[inotifyId].fd = -1;
		if (0 > inotify_rm_watch(fd, wd))
		{
			SCLogError("[%s:%d]inotify_rm_watch failed, path(%s)!",
				__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
		}
		close(fd);
		return NULL;
	}
	memset(buff, 0, SHARE_EVENT_CACHE_SIZE);

	inotifyCleanupArgs = (INOTIFY_CLEAENUP_ARGS *)SCMalloc(sizeof(INOTIFY_CLEAENUP_ARGS));
	if (NULL == inotifyCleanupArgs)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%u)!",
			__func__, __LINE__, (unsigned int)sizeof(INOTIFY_CLEAENUP_ARGS));
		g_inotifyThreadPool[inotifyId].fd = -1;
		if (0 > inotify_rm_watch(fd, wd))
		{
			SCLogError("[%s:%d]inotify_rm_watch failed, path(%s)!",
				__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
		}
		close(fd);
		SCFree(buff);
		buff = NULL;
		return NULL;
	}
	inotifyCleanupArgs->fd = fd;
	inotifyCleanupArgs->wd = wd;
	inotifyCleanupArgs->buff = buff;
	inotifyCleanupArgs->inotifyId = inotifyId;

	pthread_cleanup_push(inotifyCleanupHandler, inotifyCleanupArgs);

	g_inotifyThreadPool[inotifyId].fd = fd;
	while (0 < (len = read(fd, buff, SHARE_EVENT_CACHE_SIZE - 1)))
	{
		nread = 0;
		while (0 < len)
		{
			event = (struct inotify_event *)&buff[nread];
			for (index = 0; index < INOTIFY_EVENT_NUM; index++)
			{
				/*
				"IN_ACCESS",
				"IN_MODIFY",
				"IN_ATTRIB",
				"IN_CLOSE_WRITE",
				"IN_CLOSE_NOWRITE",
				"IN_OPEN",
				"IN_MOVED_FROM",
				"IN_MOVED_TO",
				"IN_CREATE",
				"IN_DELETE",
				"IN_DELETE_SELF",
				"IN_MOVE_SELF"
				*/
				if ((event->mask >> index) & 1)
				{
					if (0 < event->len)
					{
						if (0xFFFFFFFF == g_inotifyThreadPool[inotifyId].modifyCount)
						{
							g_inotifyThreadPool[inotifyId].modifyCount = 0;
						}
						else
						{
							g_inotifyThreadPool[inotifyId].modifyCount++;
						}
					}
				}
			}

			nread = nread + size + event->len;
			len = len - size - event->len;
		}
	}

	if (0 > inotify_rm_watch(fd, wd))
	{
		SCLogError("[%s:%d]inotify_rm_watch failed, path(%s)!",
			__func__, __LINE__, g_inotifyThreadPool[inotifyId].path);
	}

	close(fd);

	if (buff)
	{
		SCFree(buff);
		buff = NULL;
	}

	if (inotifyCleanupArgs)
	{
		SCFree(inotifyCleanupArgs);
		inotifyCleanupArgs = NULL;
	}

	pthread_cleanup_pop(0);

	return NULL;
}

/************************************************************
*Function    : startInotifyMonitor
*Action      : inotify monitor thread
*Input       : null
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int startInotifyMonitor(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder)
{
	int len;
	int inotifyId;

	if ((-1 != pconfig->inotifyId) && (-1 != g_inotifyThreadPool[pconfig->inotifyId].fd))
	{
		return PARSER_OK;
	}

	len = strlen(SHARE_SYNC_BASE_DIR) + strlen(pconfig->taskName) + strlen(localFolder->folderName) + 3;

	if (-1 != pconfig->inotifyId)
	{
		inotifyId = pconfig->inotifyId;
	}
	else
	{
		inotifyId = getInotifyId();
		if (-1 == inotifyId)
		{
			SCLogError("[%s:%d]inotify resource not enough, max(%d), task(%s)!",
				__func__, __LINE__, FILE_SYNC_CONFIG_MAX, pconfig->taskName);
			return PARSER_ERROR;
		}
	}

	if (g_inotifyThreadPool[inotifyId].path)
	{
		SCFree(g_inotifyThreadPool[inotifyId].path);
	}
	g_inotifyThreadPool[inotifyId].path = (char *)SCMalloc(len);
	if (NULL == g_inotifyThreadPool[inotifyId].path)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)!", __func__, __LINE__, len);
		return PARSER_ERROR;
	}
	if (0 > snprintf(g_inotifyThreadPool[inotifyId].path, len, "%s%s/%s3",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName))
	{
		putInotifyId(inotifyId);
		SCLogError("[%s:%d]snprintf failed, task(%s)!", __func__, __LINE__, pconfig->taskName);
		return PARSER_ERROR;
	}

	if (-1 == pconfig->inotifyId)
	{
		pconfig->inotifyId = inotifyId;
	}

	if (0 != pthread_create(&(g_inotifyThreadPool[inotifyId].id), NULL, runFileSyncInotify, &(pconfig->inotifyId)))
	{
		pconfig->inotifyId = -1;
		putInotifyId(inotifyId);
		SCLogError("[%s:%d]pthread_create failed, task(%s)!", __func__, __LINE__, pconfig->taskName);
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : configCacheSync
*Action      : config cache sync
*Input       : pconfig configuration data
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int configCacheSync(SHARE_SYNC_PARA *pconfig)
{
	int ret;

	if (RUN_AS_OUTER())
	{
		ret = clientCacheConfig(pconfig, &(pconfig->outFolder));
		if (PARSER_OK == ret)
		{
			ret = serverCacheConfig(pconfig, &(pconfig->outFolder));
		}

		/* start outer inotify monitor thread */
		if (PARSER_OK == ret)
		{
			ret = startInotifyMonitor(pconfig, &(pconfig->outFolder));
		}
	}
	else
	{
		ret = clientCacheConfig(pconfig, &(pconfig->inFolder));
		if (PARSER_OK == ret)
		{
			ret = serverCacheConfig(pconfig, &(pconfig->inFolder));
		}

		/* start inner inotify monitor thread */
		if (PARSER_OK == ret)
		{
			ret = startInotifyMonitor(pconfig, &(pconfig->inFolder));
		}
	}

	return ret;
}

/************************************************************
*Function    : isRemoteFolderEmpty
*Action      : check remote folder is empty
*Input       : pconfig          configuration data
			   remoteFolder     remote folder
			   remoteIp         remote ip
*Output      : null
*Return      : PARSER_BFALSE    ERROR
			   PARSER_BTRUE     OK
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int isRemoteFolderEmpty(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *remoteFolder, char *remoteIp)
{
	int ret;
	int cmdLen;
	char buff[SHARE_SYNC_COMM_LEN];
	char *command = NULL;

	cmdLen = (pconfig->unchangeInfo.taskNameLen * 4)
		+ pconfig->unchangeInfo.inFolderNameLen
		+ pconfig->unchangeInfo.outFolderNameLen
		+ g_fsyncUnchangeInfo->baseDirLen
		+ SHARE_SYNC_COMM_LEN
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	snprintf(command, cmdLen,
		"rsync -n --timeout=100 %s@%s::%s/%s3/ --password-file=%s%s/%s.rsync 2>/dev/null " \
		"|awk 'BEGIN{FS=\" \"}{if ($5 != \".\") print $5}END{}' |wc -l",
		pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
		SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	ret = cmd_system_getout(command, buff, SHARE_SYNC_COMM_LEN);
	if (-1 == ret)
	{
		SCLogError("[%s:%d]cmd_system_getout error, ret(%d), command(%s), buff:%s", __func__, __LINE__, ret, command, buff);
		SCFree(command);
		return PARSER_BFALSE;
	}

	if (!strncmp(buff, "0", 1))
	{
		SCFree(command);
		return PARSER_BTRUE;
	}

	SCFree(command);
	return PARSER_BFALSE;
}

/************************************************************
*Function    : getDiffFiles
*Action      : get diff file list
*Input       : pconfig          configuration data
			   localFolder      local folder
			   remoteFolder     remote folder
			   remoteIp         remote ip
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int getDiffFiles(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder,
	SHARE_FOLDER_PARA *remoteFolder, char *remoteIp)
{
	int cmdLen;
	char *command = NULL;

	cmdLen = (g_fsyncUnchangeInfo->baseDirLen * 3)
		+ (pconfig->unchangeInfo.taskNameLen * 6)
		+ ((pconfig->unchangeInfo.outFolderNameLen + pconfig->unchangeInfo.inFolderNameLen) * 2)
		+ g_fsyncUnchangeInfo->includeFileLen
		+ g_fsyncUnchangeInfo->excludeFileLen
		+ g_fsyncUnchangeInfo->diffFileLen
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	if (ALL_SYNC == pconfig->extendPara.syncType)
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s1/ && rsync -a%svn -R ./%s --timeout=100 " \
			"%s@%s::%s/%s1/ --password-file=%s%s/%s.rsync 2>/dev/null",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			(pconfig->extendPara.isDeleteSync) ? " --delete" : "",
			pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	}
	else if (INCLUDE_SYNC == pconfig->extendPara.syncType)
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s1/ && rsync -a%svn -R ./%s " \
			"--include-from=\"%s%s/%s\" --exclude=\"*\" --timeout=100 " \
			"%s@%s::%s/%s1/ --password-file=%s%s/%s.rsync 2>/dev/null",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			(pconfig->extendPara.isDeleteSync) ? " --delete" : "",
			SHARE_SYNC_BASE_DIR, pconfig->taskName,
			SHARE_INCLUDE_FILE_NAME, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	}
	else
	{
		snprintf(command, cmdLen,
			"cd %s%s/%s1/ && rsync -a%svn -R ./%s " \
			"--exclude-from=\"%s%s/%s\" --timeout=100 " \
			"%s@%s::%s/%s1/ --password-file=%s%s/%s.rsync 2>/dev/null",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			(pconfig->extendPara.isDetectDst) ? "" : "u",
			(pconfig->extendPara.isDeleteSync) ? " --delete" : "",
			SHARE_SYNC_BASE_DIR, pconfig->taskName,
			SHARE_EXCLUDE_FILE_NAME, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	}

	if (PARSER_OK != excuteCommandGetout(pconfig, localFolder, remoteFolder, command))
	{
		SCFree(command);
		command = NULL;
		return PARSER_ERROR;
	}

	snprintf(command, cmdLen, "%s%s/%s", SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_DIFF_FILE_NAME);
	if (0 != access(command, 0))
	{
		SCFree(command);
		command = NULL;
		SCLogError("[%s:%d]get diff file failed, task(%s)", __func__, __LINE__, pconfig->taskName);
		return PARSER_ERROR;
	}

	/* delete line: null, ./, deleting... */
	snprintf(command, cmdLen, "sed -i '/.\\//d;/^$/d;/^deleting /d' %s%s/%s",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_DIFF_FILE_NAME);
	(void)excuteCommand(command, PARSER_BFALSE);

	SCFree(command);
	command = NULL;

	return PARSER_OK;
}

/************************************************************
*Function    : syncDiffFiles
*Action      : sync diff file list
*Input       : pconfig          configuration data
			   localFolder      local folder
			   remoteFolder     remote folder
			   remoteIp         remote ip
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int syncDiffFiles(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder,
	SHARE_FOLDER_PARA *remoteFolder, char *remoteIp)
{
	int cmdLen;
	char *command = NULL;

	cmdLen = (g_fsyncUnchangeInfo->baseDirLen * 4)
		+ (pconfig->unchangeInfo.taskNameLen * 7)
		+ ((pconfig->unchangeInfo.outFolderNameLen + pconfig->unchangeInfo.inFolderNameLen) * 2)
		+ g_fsyncUnchangeInfo->includeFileLen
		+ g_fsyncUnchangeInfo->excludeFileLen
		+ g_fsyncUnchangeInfo->tmpDstFileLen
		+ g_fsyncUnchangeInfo->oldDstFileLen
		+ g_fsyncUnchangeInfo->newDstFileLen
		+ SHARE_SYNC_COMM_LEN
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	/* delete */
	if (pconfig->extendPara.isDeleteSync)
	{
		if (ALL_SYNC == pconfig->extendPara.syncType)
		{
			snprintf(command, cmdLen,
				"cd %s%s/%s1/ && rsync -auv -R ./ --delete --exclude-from=\"%s%s/%s\" --timeout=100 " \
				"%s@%s::%s/%s1/ --password-file=%s%s/%s.rsync >/dev/null 2>&1",
				SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
				SHARE_SYNC_BASE_DIR, pconfig->taskName,
				SHARE_DIFF_FILE_NAME, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
				SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		}
		else if (INCLUDE_SYNC == pconfig->extendPara.syncType)
		{
			snprintf(command, cmdLen,
				"diff %s%s/%s %s%s/%s |awk '/^>/ || /^</ {print $2}' > %s%s/%s",
				SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_DIFF_FILE_NAME,
				SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_INCLUDE_FILE_NAME,
				SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_DELETE_FILE_NAME);
			(void)excuteCommand(command, PARSER_BFALSE);

			snprintf(command, cmdLen,
				"cd %s%s/%s1/ && rsync -auv -R ./ --delete --include-from=\"%s%s/%s\" --exclude=\"*\"" \
				" --timeout=100 %s@%s::%s/%s1/ --password-file=%s%s/%s.rsync >/dev/null 2>&1",
				SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
				SHARE_SYNC_BASE_DIR, pconfig->taskName,
				SHARE_DELETE_FILE_NAME, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
				SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		}
		else
		{
			snprintf(command, cmdLen,
				"cd %s%s/%s1/ && rsync -auv -R ./ --delete " \
				"--exclude-from=\"%s%s/%s\" --exclude-from=\"%s%s/%s\" --timeout=100 " \
				"%s@%s::%s/%s1/ --password-file=%s%s/%s.rsync >/dev/null 2>&1",
				SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
				SHARE_SYNC_BASE_DIR, pconfig->taskName,
				SHARE_DIFF_FILE_NAME, SHARE_SYNC_BASE_DIR, pconfig->taskName,
				SHARE_EXCLUDE_FILE_NAME, pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
				SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
		}

		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			SCFree(command);
			return PARSER_ERROR;
		}
	}

	/* sync to local cache dirtory */
	snprintf(command, cmdLen,
		"rsync -avz --include-from=\"%s%s/%s\" --exclude=\"*\" %s%s/%s1/ %s%s/%s2/ >/dev/null 2>&1",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_DIFF_FILE_NAME,
		SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
		SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName);
	if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
	{
		SCFree(command);
		return PARSER_ERROR;
	}

	/* sync local cache to remote dirtory */
	snprintf(command, cmdLen,
		"cd %s%s/%s2/ && rsync -av -R ./ %s@%s::%s/%s3/ --password-file=%s%s/%s.rsync >/dev/null 2>&1",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
		pconfig->taskName, remoteIp, pconfig->taskName, remoteFolder->folderName,
		SHARE_SYNC_BASE_DIR, pconfig->taskName, pconfig->taskName);
	if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
	{
		SCFree(command);
		return PARSER_ERROR;
	}

	snprintf(command, cmdLen, "rm -rf %s%s/%s2/*",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName);
	(void)excuteCommand(command, PARSER_BFALSE);

	SCFree(command);
	return PARSER_OK;
}

/************************************************************
*Function    : handleCacheLocalFile
*Action      : handle cache local file after sync
*Input       : pconfig          configuration data
			   localFolder      local folder
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.5.3
*Instruction : null
************************************************************/
static void handleCacheLocalFile(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder)
{
	int len;
	FILE *fp = NULL;
	char *buff = NULL;
	char *path = NULL;

	len = g_fsyncUnchangeInfo->baseDirLen
		+ pconfig->unchangeInfo.taskNameLen
		+ g_fsyncUnchangeInfo->diffFileLen
		+ 2;
	path = (char *)SCMalloc(len);
	if (NULL == path)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, len);
		return;
	}

	if (0 > snprintf(path, len, "%s%s/%s", SHARE_SYNC_BASE_DIR, pconfig->taskName, SHARE_DIFF_FILE_NAME))
	{
		SCLogError("[%s:%d]snprintf failed, task(%s)!", __func__, __LINE__, pconfig->taskName);
		SCFree(path);
		return;
	}

	buff = (char *)SCMalloc(SHARE_EVENT_CACHE_SIZE);
	if (NULL == buff)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, SHARE_EVENT_CACHE_SIZE);
		SCFree(path);
		return;
	}
	memset(buff, 0, SHARE_EVENT_CACHE_SIZE);

	fp = fopen(path, "r");
	if (NULL == fp)
	{
		SCLogError("[%s:%d]fopen failed, path(%s), task(%s)", __func__, __LINE__, path, pconfig->taskName);
		SCFree(buff);
		SCFree(path);
		return;
	}

	fread(buff, 1, SHARE_EVENT_CACHE_SIZE - 1, fp);

	if (0 != fclose(fp))
	{
		SCLogError("[%s:%d]fclose failed, path(%s), task(%s)", __func__, __LINE__, path, pconfig->taskName);
		SCFree(buff);
		SCFree(path);
		return;
	}

	handleLocalFile(buff, pconfig, localFolder);

	SCFree(buff);
	buff = NULL;
	SCFree(path);
	buff = NULL;
	return;
}

/************************************************************
*Function    : syncCacheDirtory
*Action      : sync cache dirtory
*Input       : pconfig          configuration data
			   localFolder      local folder
			   remoteFolder     remote folder
			   remoteIp         remote ip
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static void syncCacheDirtory(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder,
	SHARE_FOLDER_PARA *remoteFolder, char *remoteIp)
{
	int ret;

	/* check remote folder is empty */
	if (!isRemoteFolderEmpty(pconfig, remoteFolder, remoteIp))
	{
		SCLogInfo("[%s:%d]remote dirtory(%s3->%s1) syncing, task(%s).",
			__func__, __LINE__, remoteFolder->folderName,
			remoteFolder->folderName, pconfig->taskName);
		return;
	}

	/* get diff file list */
	ret = getDiffFiles(pconfig, localFolder, remoteFolder, remoteIp);
	if (PARSER_OK != ret)
	{
		if (pconfig->isSyncSuccess)
		{
			pconfig->isSyncSuccess = PARSER_BFALSE;
		}
		return;
	}

	/* sync diff file */
	ret = syncDiffFiles(pconfig, localFolder, remoteFolder, remoteIp);
	if (PARSER_OK != ret)
	{
		if (pconfig->isSyncSuccess)
		{
			pconfig->isSyncSuccess = PARSER_BFALSE;
		}
		return;
	}

	if (!pconfig->isSyncSuccess)
	{
		pconfig->isSyncSuccess = PARSER_BTRUE;
		SCLogInfo("[%s:%d]sync task success, task(%s).", __func__, __LINE__, pconfig->taskName);
	}

	/* handle local file after sync */
	handleCacheLocalFile(pconfig, localFolder);

	return;
}

/************************************************************
*Function    : isCachingToLocal
*Action      : check cache files to local
*Input       : pconfig          configuration data
*Output      : null
*Return      : PARSER_BTRUE    OK
			   PARSER_BFALSE   ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int isCachingToLocal(SHARE_SYNC_PARA *pconfig)
{
	unsigned int modifyCount;

	modifyCount = g_inotifyThreadPool[pconfig->inotifyId].modifyCount;
	sleep(1);
	if (modifyCount != g_inotifyThreadPool[pconfig->inotifyId].modifyCount)
	{
		return PARSER_BTRUE;
	}
	return PARSER_BFALSE;
}

/************************************************************
*Function    : syncRemoteToLocal
*Action      : sync remote file list to local
*Input       : pconfig          configuration data
			   localFolder      local folder
*Output      : null
*Return      : PARSER_OK        OK
			   PARSER_ERROR     ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int syncRemoteToLocal(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder)
{
	int ret;
	int cmdLen;
	char buff[SHARE_SYNC_COMM_LEN];
	char *command = NULL;

	cmdLen = (g_fsyncUnchangeInfo->baseDirLen * 2)
		+ ((pconfig->unchangeInfo.outFolderNameLen + pconfig->unchangeInfo.inFolderNameLen) * 2)
		+ (pconfig->unchangeInfo.taskNameLen * 2)
		+ SHARE_SYNC_COMMAND_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	snprintf(command, cmdLen, "ls -A %s%s/%s3/ |wc -l",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName);
	ret = cmd_system_getout(command, buff, SHARE_SYNC_COMM_LEN);
	if (-1 == ret)
	{
		SCLogError("[%s:%d]cmd_system_getout error, ret(%d), command(%s), buff:%s", __func__, __LINE__, ret, command, buff);
		SCFree(command);
		return PARSER_ERROR;
	}

	if (strncmp(buff, "0", 1))
	{
		snprintf(command, cmdLen, "rsync -av%sz --suffix=%s %s%s/%s3/ %s%s/%s1/ >/dev/null 2>&1",
			(pconfig->extendPara.isChangeName) ? "b" : "", SHARE_SUFFIX_STRING,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName,
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			SCFree(command);
			return PARSER_ERROR;
		}

		snprintf(command, cmdLen, "rm -rf %s%s/%s3/*",
			SHARE_SYNC_BASE_DIR, pconfig->taskName, localFolder->folderName);
		(void)excuteCommand(command, PARSER_BFALSE);
	}

	SCFree(command);
	return PARSER_OK;
}

/************************************************************
*Function    : syncRemoteCacheDirtory
*Action      : sync remote cache file list
*Input       : pconfig          configuration data
			   localFolder      local folder
			   remoteFolder     remote folder
*Output      : null
*Return      : PARSER_OK        OK
			   PARSER_ERROR     ERROR
			   PARSER_CONTINUE  CONTINUE
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int syncRemoteCacheDirtory(SHARE_SYNC_PARA *pconfig, SHARE_FOLDER_PARA *localFolder, SHARE_FOLDER_PARA *remoteFolder)
{
	/* check syncing remote dirtory to local */
	if (!isCachingToLocal(pconfig))
	{
		/* sync remote cache dirtory to local */
		return syncRemoteToLocal(pconfig, localFolder);
	}
	SCLogInfo("[%s:%d]remote to local dirtory(%s2->%s3) syncing, task(%s).",
		__func__, __LINE__, remoteFolder->folderName, localFolder->folderName, pconfig->taskName);
	return PARSER_CONTINUE;
}

/************************************************************
*Function    : syncTaskProcess
*Action      : thread       timer para
*Input       : null
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int syncTaskProcess(struct thread *thread)
{
	SHARE_SYNC_PARA *pconfig = NULL;

	pconfig = (SHARE_SYNC_PARA *)(thread->arg);
	SCLogInfo("[%s:%d]Trigger timer(%p), taskName(%s).", __func__, __LINE__, pconfig->timer, pconfig->taskName);
	pconfig->timer = NULL;

	if (g_isCache)
	{
		if (PARSER_OK != configCacheSync(pconfig))
		{
			return syncTimerRepeat(pconfig);
		}

		if (RUN_AS_OUTER())
		{
			if (OUT_TO_IN == pconfig->direction)
			{
				syncCacheDirtory(pconfig, &(pconfig->outFolder), &(pconfig->inFolder), INNER_DEFAULT_IP_STR);
			}
			else if (IN_TO_OUT == pconfig->direction)
			{
				(void)syncRemoteCacheDirtory(pconfig, &(pconfig->outFolder), &(pconfig->inFolder));
			}
			else
			{
				if (PARSER_OK == syncRemoteCacheDirtory(pconfig, &(pconfig->outFolder), &(pconfig->inFolder)))
				{
					syncCacheDirtory(pconfig, &(pconfig->outFolder), &(pconfig->inFolder), INNER_DEFAULT_IP_STR);
				}
			}
		}
		else if (RUN_AS_INNER())
		{
			if (IN_TO_OUT == pconfig->direction)
			{
				syncCacheDirtory(pconfig, &(pconfig->inFolder), &(pconfig->outFolder), OUTER_DEFAULT_IP_STR);
			}
			else if (OUT_TO_IN == pconfig->direction)
			{
				(void)syncRemoteCacheDirtory(pconfig, &(pconfig->inFolder), &(pconfig->outFolder));
			}
			else
			{
				if (PARSER_OK == syncRemoteCacheDirtory(pconfig, &(pconfig->inFolder), &(pconfig->outFolder)))
				{
					syncCacheDirtory(pconfig, &(pconfig->inFolder), &(pconfig->outFolder), OUTER_DEFAULT_IP_STR);
				}
			}
		}
	}
	else
	{
		if (PARSER_OK != configSync(pconfig))
		{
			return syncTimerRepeat(pconfig);
		}

		if (RUN_AS_OUTER())
		{
			if ((OUT_TO_IN == pconfig->direction) || (OUT_AND_IN == pconfig->direction))
			{
				syncDirtory(pconfig, &(pconfig->outFolder), &(pconfig->inFolder), INNER_DEFAULT_IP_STR);
			}
		}
		else if (RUN_AS_INNER())
		{
			if ((IN_TO_OUT == pconfig->direction) || (OUT_AND_IN == pconfig->direction))
			{
				syncDirtory(pconfig, &(pconfig->inFolder), &(pconfig->outFolder), OUTER_DEFAULT_IP_STR);
			}
		}
	}

	syncTimerRepeat(pconfig);

	return PARSER_OK;
}

/************************************************************
*Function    : syncTimerRepeat
*Action      : timer repeat
*Input       : pconfig configuration data
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.5
*Instruction : null
************************************************************/
int syncTimerRepeat(SHARE_SYNC_PARA *pconfig)
{
	struct thread *timerHandle = NULL;

	if (SYNC_CONFIG_VALID != pconfig->configState)
	{
		return PARSER_OK;
	}

	pthread_mutex_lock(&(pconfig->timerLock));
	if (pconfig->timer)
	{
		SCLogInfo("[%s:%d]timer(%p) is existed.", __func__, __LINE__, pconfig->timer);
		pthread_mutex_unlock(&(pconfig->timerLock));
		return PARSER_OK;
	}

	if (IMMEDIATELY_SYNC == pconfig->extendPara.planType)
	{
		/* loop set interval seconds */
		timerHandle = thread_add_timer(g_syncMaster, syncTaskProcess, pconfig, pconfig->extendPara.intervalTime);
	}
	else
	{
		/* loop one day */
		timerHandle = thread_add_timer(g_syncMaster, syncTaskProcess, pconfig, SECONDS_PER_DAY);
	}

	if (NULL == timerHandle)
	{
		SCLogError("[%s:%d]create timer task failed!", __func__, __LINE__);
		pthread_mutex_unlock(&(pconfig->timerLock));
		return PARSER_ERROR;
	}
	pconfig->timer = timerHandle;
	SCLogInfo("[%s:%d]create timer task success, timer(%p).", __func__, __LINE__, pconfig->timer);
	pthread_mutex_unlock(&(pconfig->timerLock));

	return PARSER_OK;
}

/************************************************************
*Function    : getCurrentClockSeconds
*Action      : get current clock(24) seconds
*Input       : null
*Output      : null
*Return      : seconds
*Author      : liuzongquan(000932)
*Date        : 2017.3.31
*Instruction : null
************************************************************/
static unsigned int getCurrentClockSeconds(void)
{
	struct tm *tmp = NULL;
	struct timeval my_timer;

	gettimeofday(&my_timer, NULL);
	tmp = localtime(&my_timer.tv_sec);
	return (unsigned int)(tmp->tm_hour * SECONDS_PER_HOUR + tmp->tm_min * SECONDS_PER_MIN + tmp->tm_sec);
}

/************************************************************
*Function    : createTimerTask
*Action      : create timer task
*Input       : pconfig configuration data
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
static int createTimerTask(SHARE_SYNC_PARA *pconfig)
{
	unsigned int seconds;
	struct thread *timerHandle = NULL;

	if (SYNC_CONFIG_INVALID == pconfig->configState)
	{
		SCLogInfo("[%s:%d]config state is invalid, not create timer task.", __func__, __LINE__);
		return PARSER_OK;
	}

	pthread_mutex_lock(&(pconfig->timerLock));
	if (pconfig->timer)
	{
		SCLogInfo("[%s:%d]timer(%p) is existed.", __func__, __LINE__, pconfig->timer);
		pthread_mutex_unlock(&(pconfig->timerLock));
		return PARSER_OK;
	}

	if (IMMEDIATELY_SYNC == pconfig->extendPara.planType)
	{
		seconds = pconfig->extendPara.intervalTime;
	}
	else
	{
		seconds = getCurrentClockSeconds();
		if (seconds <= pconfig->extendPara.intervalTime)
		{
			seconds = pconfig->extendPara.intervalTime - seconds;
		}
		else
		{
			seconds = SECONDS_PER_DAY - (seconds - pconfig->extendPara.intervalTime);
		}
	}

	timerHandle = thread_add_timer(g_syncMaster, syncTaskProcess, pconfig, seconds);
	if (NULL == timerHandle)
	{
		SCLogError("[%s:%d]create timer task failed!", __func__, __LINE__);
		pthread_mutex_unlock(&(pconfig->timerLock));
		return PARSER_ERROR;
	}
	pconfig->timer = timerHandle;
	SCLogInfo("[%s:%d]create timer task success, timer(%p).", __func__, __LINE__, pconfig->timer);
	pthread_mutex_unlock(&(pconfig->timerLock));

	return PARSER_OK;
}

/************************************************************
*Function    : getConfigByTaskName
*Action      : get config by task name
*Input       : taskName     task name
*Output      : null
*Return      : config node
			   NULL: not find
*Author      : liuzongquan(000932)
*Date        : 2017.3.31
*Instruction : null
************************************************************/
static SHARE_SYNC_PARA *getConfigByTaskName(const char *taskName)
{
	SHARE_SYNC_PARA *pconfig = NULL;

	pthread_rwlock_rdlock(&g_fileSyncLock);
	list_for_each_entry(pconfig, &g_fileSyncConfig, node)
	{
		if (!strncmp(pconfig->taskName, taskName, strlen(pconfig->taskName)))
		{
			pthread_rwlock_unlock(&g_fileSyncLock);
			return pconfig;
		}
	}
	pthread_rwlock_unlock(&g_fileSyncLock);

	return NULL;
}

/************************************************************
*Function    : setJsonStatus
*Action      : set json status
*Input       : jsonObj json obj
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.7
*Instruction : value (0:disable 1:enable)
************************************************************/
static int setJsonStatus(struct json_object *jsonObj, int value)
{
	int ret;
	struct json_object *pval = NULL;

	if (NULL == jsonObj)
	{
		SCLogError("[%s:%d]invalid jsonObj(%p)", __func__, __LINE__, jsonObj);
		return PARSER_ERROR;
	}

	SCLogInfo("[%s:%d]before, json obj:%s", __func__, __LINE__, JSON_FORMAT_STR(jsonObj));

	pval = jobj_get_obj(jsonObj, SYNC_CONFIG_SWITCH);
	if (NULL == pval)
	{
		SCLogWarning("[%s:%d]not find json object of key(%s)", __func__, __LINE__, SYNC_CONFIG_SWITCH);
	}

	ret = jobj_set_int(jsonObj, SYNC_CONFIG_SWITCH, value);
	if (-1 == ret)
	{
		SCLogError("[%s:%d]set value of key(%s) to %d failed", __func__, __LINE__, SYNC_CONFIG_SWITCH, value);
		return PARSER_ERROR;
	}

	SCLogInfo("[%s:%d]after, json obj:%s", __func__, __LINE__, JSON_FORMAT_STR(jsonObj));

	return PARSER_OK;
}

/************************************************************
*Function    : setOneConfigEnable
*Action      : set one configuration enable
*Input       : taskName     task name
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.30
*Instruction : null
************************************************************/
int setOneConfigEnable(const char *taskName)
{
	SHARE_SYNC_PARA *pconfig = NULL;

	/* get config */
	pconfig = getConfigByTaskName(taskName);
	if (NULL == pconfig)
	{
		SCLogWarning("[%s:%d]not find config of task name(%s)", __func__, __LINE__, taskName);
		return PARSER_OK;
	}

	/* check enable already */
	if ((SYNC_CONFIG_VALID == pconfig->configState) && (pconfig->timer))
	{
		SCLogInfo("[%s:%d]enable already, task name(%s)", __func__, __LINE__, taskName);
		return PARSER_OK;
	}

	/* modify json status (0:disable 1:enable) */
	if (PARSER_OK != setJsonStatus(pconfig->json, 1))
	{
		return PARSER_ERROR;
	}

	/* set task valid */
	pconfig->configState = SYNC_CONFIG_VALID;

	/* add timer */
	if (PARSER_OK != createTimerTask(pconfig))
	{
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : setOneConfigDisable
*Action      : set one config disable
*Input       : taskName     task name
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.30
*Instruction : null
************************************************************/
int setOneConfigDisable(const char *taskName)
{
	SHARE_SYNC_PARA *pconfig = NULL;

	/* get config */
	pconfig = getConfigByTaskName(taskName);
	if (NULL == pconfig)
	{
		SCLogWarning("[%s:%d]not find config of task name(%s)", __func__, __LINE__, taskName);
		return PARSER_OK;
	}

	/* check enable already */
	if ((SYNC_CONFIG_INVALID == pconfig->configState) && (NULL == pconfig->timer))
	{
		SCLogInfo("[%s:%d]enable already, task name(%s)", __func__, __LINE__, taskName);
		return PARSER_OK;
	}

	/* modify json status (0:disable 1:enable) */
	if (PARSER_OK != setJsonStatus(pconfig->json, 0))
	{
		return PARSER_ERROR;
	}

	/* set task invalid */
	pconfig->configState = SYNC_CONFIG_INVALID;

	/* cancel task */
	if (pconfig->timer)
	{
		thread_cancel(pconfig->timer);
		SCLogInfo("[%s:%d]cancel timer(%p).", __func__, __LINE__, pconfig->timer);
		pconfig->timer = NULL;
	}

	return PARSER_OK;
}

/************************************************************
*Function    : unmountTask
*Action      : umount task directory
*Input       : pconfig  pconfig
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.25
*Instruction : null
************************************************************/
static int unmountTask(SHARE_SYNC_PARA *pconfig)
{
	int cmdLen;
	char *command = NULL;
	SHARE_FOLDER_PARA *pfolder = NULL;

	if (RUN_AS_OUTER())
	{
		pfolder = &(pconfig->outFolder);
	}
	else
	{
		pfolder = &(pconfig->inFolder);
	}

	cmdLen = g_fsyncUnchangeInfo->baseDirLen
		+ pconfig->unchangeInfo.taskNameLen
		+ pconfig->unchangeInfo.inFolderNameLen
		+ pconfig->unchangeInfo.outFolderNameLen
		+ SHARE_SYNC_COMM_LEN;
	command = (char *)SCMalloc(cmdLen);
	if (NULL == command)
	{
		SCLogInfo("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, cmdLen);
		return PARSER_ERROR;
	}

	snprintf(command, cmdLen, "mount |grep \"%s%s/%s%s\" |wc -l",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, pfolder->folderName, g_isCache ? "1" : "");
	if (!isAlreadyMount(command))
	{
		SCFree(command);
		return PARSER_OK;
	}

	snprintf(command, cmdLen, "umount %s%s/%s%s",
		SHARE_SYNC_BASE_DIR, pconfig->taskName, pfolder->folderName, g_isCache ? "1" : "");
	if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
	{
		SCFree(command);
		return PARSER_BUSY;
	}

	snprintf(command, cmdLen, "rm -rf %s%s", SHARE_SYNC_BASE_DIR, pconfig->taskName);
	(void)excuteCommand(command, PARSER_BFALSE);

	SCFree(command);
	return PARSER_OK;
}

/************************************************************
*Function    : umountDirectoryList
*Action      : analy mount directory list and umount
*Input       : dirList      mount directory list
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int umountDirectoryList(char *dirList)
{
	char *ptemp = NULL;
	char *outptr = NULL;
	char command[SHARE_SYNC_COMMAND_LEN];

	ptemp = strtok_r(dirList, ",", &outptr);
	while (ptemp)
	{
		snprintf(command, SHARE_SYNC_COMMAND_LEN, "umount -f %s", ptemp);
		if (PARSER_OK != excuteCommand(command, PARSER_BTRUE))
		{
			return PARSER_ERROR;
		}
		SCLogInfo("[%s:%d]umount %s success.", __func__, __LINE__, ptemp);

		ptemp = strtok_r(NULL, ",", &outptr);
	}
	return PARSER_OK;
}

/************************************************************
*Function    : umountRsyncDirtory
*Action      : umount all rsync directory when restart gap20
*Input       : path     mount directory
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int umountRsyncDirtory(char *path)
{
	int ret;
	int count;
	char *buff = NULL;
	char command[SHARE_SYNC_COMMAND_LEN];

	buff = (char *)SCMalloc(SHARE_EVENT_CACHE_SIZE);
	if (NULL == buff)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)", __func__, __LINE__, SHARE_EVENT_CACHE_SIZE);
		return PARSER_ERROR;
	}

	snprintf(command, SHARE_SYNC_COMMAND_LEN, "mount |grep \"%s\" |awk 'BEGIN{FS=\" \"}{print $3}END{}'", path);
	count = cmd_system_getout(command, buff, SHARE_EVENT_CACHE_SIZE);
	if (0 > count)
	{
		SCLogError("[%s:%d]cmd_system_getout error, ret(%d), command(%s)", __func__, __LINE__, count, command);
		SCFree(buff);
		buff = NULL;
		return PARSER_ERROR;
	}
	buff[count] = '\0';

	ret = umountDirectoryList(buff);
	if (PARSER_OK != ret)
	{
		SCLogError("[%s:%d]direcotry being used, can not umount!", __func__, __LINE__);
	}

	SCFree(buff);
	buff = NULL;

	return ret;
}

/************************************************************
*Function    : delOneConfig
*Action      : delete one config
*Input       : taskName     task name
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
			   PARSER_USED  USED
			   PARSER_BUSY  BUSY
*Author      : liuzongquan(000932)
*Date        : 2017.3.30
*Instruction : null
************************************************************/
int delOneConfig(const char *taskName)
{
	int ret;
	int cmdLen;
	char *command = NULL;
	SHARE_SYNC_PARA *pconfig = NULL;

	/* get config */
	pconfig = getConfigByTaskName(taskName);
	if (NULL == pconfig)
	{
		cmdLen = g_fsyncUnchangeInfo->baseDirLen + strlen(taskName) + 8;
		command = (char *)SCMalloc(cmdLen);
		if (NULL == command)
		{
			SCLogError("[%s:%d]SCMalloc memory failed, size(%d).", __func__, __LINE__, cmdLen);
			return PARSER_ERROR;
		}

		snprintf(command, cmdLen, "rm -rf %s%s", SHARE_SYNC_BASE_DIR, taskName);
		(void)excuteCommand(command, PARSER_BFALSE);
		SCFree(command);
		return PARSER_OK;
	}

	SCLogInfo("[%s:%d]exist old task(%s), to delete.", __func__, __LINE__, pconfig->taskName);

	/* set task invalid */
	pconfig->configState = SYNC_CONFIG_INVALID;

	if (pconfig->timer)
	{
		SCLogInfo("[%s:%d]cancel timer(%p).", __func__, __LINE__, pconfig->timer);
		thread_cancel(pconfig->timer);
		pconfig->timer = NULL;
	}

	/* umount */
	ret = unmountTask(pconfig);
	if (PARSER_OK != ret)
	{
		/* set task valid */
		pconfig->configState = SYNC_CONFIG_VALID;

		/* add timer */
		if (PARSER_OK != createTimerTask(pconfig))
		{
			return PARSER_ERROR;
		}

		return ret;
	}

	/* clear rule */
	if (PARSER_OK != rsync_remove_module(SHARE_SYNC_CONFIG_PATH, taskName))
	{
		SCLogError("[%s:%d]rsync_remove_module failed, group(%s)", __func__, __LINE__, taskName);
	}

	freeConfigNode(pconfig);
	return PARSER_OK;
}

/************************************************************
*Function    : isConfigValid
*Action      : check config valid
*Input       : pconfig configuration data
*Output      : null
*Return      : PARSER_BTRUE    OK
			   PARSER_BFALSE   ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.31
*Instruction : null
************************************************************/
static int isConfigValid(SHARE_SYNC_PARA *pconfig)
{
	/* check board type */
	if (!RUN_AS_OUTER() && !RUN_AS_INNER())
	{
		SCLogError("[%s:%d]can not config in arbiter board!", __func__, __LINE__);
		return PARSER_BFALSE;
	}

	/* check config switch-state */
	if ((SYNC_CONFIG_VALID != pconfig->configState) && (SYNC_CONFIG_INVALID != pconfig->configState))
	{
		SCLogError("[%s:%d]not valid status(%d)!", __func__, __LINE__, pconfig->configState);
		return PARSER_BFALSE;
	}

	/* check direction */
	if ((OUT_TO_IN > pconfig->direction) || (SYNC_DIRECTION_BUTT <= pconfig->direction))
	{
		SCLogError("[%s:%d]invalid direction(%d) config", __func__, __LINE__, pconfig->direction);
		return PARSER_BFALSE;
	}

	/* check plan type */
	if ((IMMEDIATELY_SYNC > pconfig->extendPara.planType) || (PLAN_TYPE_BUTT <= pconfig->extendPara.planType))
	{
		SCLogError("[%s:%d]invalid planType(%d) config", __func__, __LINE__, pconfig->extendPara.planType);
		return PARSER_BFALSE;
	}

	/* check sync type */
	if ((ALL_SYNC > pconfig->extendPara.syncType) || (SYNC_TYPE_BUTT <= pconfig->extendPara.syncType))
	{
		SCLogError("[%s:%d]invalid syncType(%d) config", __func__, __LINE__, pconfig->extendPara.syncType);
		return PARSER_BFALSE;
	}

	return PARSER_BTRUE;
}

/************************************************************
*Function    : addOneConfig
*Action      : add one configuration
*Input       : pconfig configuration data
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
			   PARSER_USED  USED
			   PARSER_BUSY  BUSY
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
int addOneConfig(SHARE_SYNC_PARA *pconfig)
{
	int ret;

	/* check config */
	if (!isConfigValid(pconfig))
	{
		return PARSER_ERROR;
	}

	/* clear old task config */
	ret = delOneConfig(pconfig->taskName);
	if (PARSER_OK != ret)
	{
		return ret;
	}

	/* add timer */
	if (PARSER_OK != createTimerTask(pconfig))
	{
		return PARSER_ERROR;
	}

	/* save config */
	pthread_rwlock_wrlock(&g_fileSyncLock);
	list_add_tail(&pconfig->node, &g_fileSyncConfig);
	pthread_rwlock_unlock(&g_fileSyncLock);

	return PARSER_OK;
}

/************************************************************
*Function    : initRsyncConfig
*Action      : init rsync config
*Input       : null
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static int initRsyncConfig(void)
{
	GError *error = NULL;
	GKeyFile *keyfile = NULL;

	keyfile = g_key_file_new();
	if (NULL == keyfile)
	{
		SCLogError("[%s:%d]g_key_file_new failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (!g_file_set_contents(SHARE_SYNC_CONFIG_PATH, SHARE_SYNC_DEFAULT_CONFIG, -1, &error))
	{
		SCLogError("[%s:%d]g_file_set_contents failed, error reason:%s", __func__, __LINE__, error->message);
		g_clear_error(&error);
		g_key_file_free(keyfile);
		return PARSER_ERROR;
	}

	g_key_file_free(keyfile);
	return PARSER_OK;
}

/************************************************************
*Function    : runFileSync
*Action      : run file rsync timer
*Input       : args
*Output      : null
*Return      : null
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
static void *runFileSync(void *args)
{
	while (thread_fetch(g_syncMaster, &g_syncTimerthread))
	{
		thread_call(&g_syncTimerthread);
	}
	return NULL;
}

/************************************************************
*Function    : syncMasterFun
*Action      : master function
*Input       : null
*Output      : null
*Return      : 0
*Author      : liuzongquan(000932)
*Date        : 2017.4.13
*Instruction : null
************************************************************/
int syncMasterFun(struct thread *t)
{
	thread_add_timer(g_syncMaster, syncMasterFun, NULL, 10);
	return 0;
}

/************************************************************
*Function    : inotifyMonitorInit
*Action      : inotify monitor thread init
*Input       : null
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.4.27
*Instruction : null
************************************************************/
static int inotifyMonitorInit(void)
{
	int size;
	int index;

	if (0 != pthread_mutex_init(&g_inotifyLock, NULL))
	{
		SCLogError("[%s:%d]init inotify mutex failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}

	size = sizeof(INOTIFY_THREAD_INFO) * FILE_SYNC_CONFIG_MAX;
	g_inotifyThreadPool = (INOTIFY_THREAD_INFO *)SCMalloc(size);
	if (NULL == g_inotifyThreadPool)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)!", __func__, __LINE__, size);
		return PARSER_ERROR;
	}
	memset(g_inotifyThreadPool, 0, size);
	for (index = 0; index < FILE_SYNC_CONFIG_MAX; index++)
	{
		g_inotifyThreadPool[index].fd = -1;
	}

	return PARSER_OK;
}

static int fsyncGetUnchangeInfo(void)
{
	g_fsyncUnchangeInfo = (FSYNC_UNCHANGE_INFO *)SCMalloc(sizeof(FSYNC_UNCHANGE_INFO));
	if (NULL == g_fsyncUnchangeInfo)
	{
		SCLogError("[%s:%d]SCMalloc memory failed, size(%d)!", __func__, __LINE__, (int)sizeof(FSYNC_UNCHANGE_INFO));
		return PARSER_ERROR;
	}
	g_fsyncUnchangeInfo->baseDirLen = strlen(SHARE_SYNC_BASE_DIR);
	g_fsyncUnchangeInfo->diffFileLen = strlen(SHARE_DIFF_FILE_NAME);
	g_fsyncUnchangeInfo->deleteFileLen = strlen(SHARE_DELETE_FILE_NAME);
	g_fsyncUnchangeInfo->includeFileLen = strlen(SHARE_INCLUDE_FILE_NAME);
	g_fsyncUnchangeInfo->excludeFileLen = strlen(SHARE_EXCLUDE_FILE_NAME);
	g_fsyncUnchangeInfo->tmpDstFileLen = strlen(SHARE_TMP_DST_EXIST_NAME);
	g_fsyncUnchangeInfo->oldDstFileLen = strlen(SHARE_OLD_DST_EXIST_NAME);
	g_fsyncUnchangeInfo->newDstFileLen = strlen(SHARE_NEW_DST_EXIST_NAME);

	return PARSER_OK;
}

/************************************************************
*Function    : file_sync_init
*Action      : sync init
*Input       : null
*Output      : null
*Return      : PARSER_OK    OK
			   PARSER_ERROR ERROR
*Author      : liuzongquan(000932)
*Date        : 2017.3.28
*Instruction : null
************************************************************/
int file_sync_init(void)
{
	/* get unchange info */
	fsyncGetUnchangeInfo();

	/* umount directory */
	if (PARSER_OK != umountRsyncDirtory(SHARE_SYNC_BASE_DIR))
	{
		return PARSER_ERROR;
	}

	if (PARSER_OK != initRsyncConfig())
	{
		return PARSER_ERROR;
	}

	if (0 != pthread_rwlock_init(&g_fileSyncLock, NULL))
	{
		SCLogError("[%s:%d]init file-sync rwlock failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}
	INIT_LIST_HEAD(&g_fileSyncConfig);

	g_syncMaster = thread_master_create();
	if (NULL == g_syncMaster)
	{
		SCLogError("[%s:%d]thread_master_create failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (NULL == thread_add_timer(g_syncMaster, syncMasterFun, NULL, 0))
	{
		SCLogError("[%s:%d]thread_add_timer failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (0 != pthread_create(&g_syncThread, NULL, runFileSync, NULL))
	{
		SCLogError("[%s:%d]pthread_create failed!", __func__, __LINE__);
		return PARSER_ERROR;
	}

	if (PARSER_OK != inotifyMonitorInit())
	{
		return PARSER_ERROR;
	}

	return PARSER_OK;
}

