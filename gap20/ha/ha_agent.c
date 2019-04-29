#include <pthread.h>

#include "zebra.h"
#include "vty.h"
#include "command.h"
#include "app_common.h"
#include "util-lock.h"
#include "ha.h"
#include "ha_agent.h"

static int g_nServerFd = 0;
static HaState g_nPrevState[2] = { 0 };
static HaAppControl* g_pHaAppControl = NULL;

extern char* config_file;
extern char* config_default_dir;
static void* haa_ctrl_loopthread(void* args);
static int HaAgentRecv(struct thread* t);

void haa_cold_sync(int fd)
{	
	struct vty* vty = vty_new();
	vty->wfd = fd;				//STDOUT_FILENO;
	vty->type = VTY_FILE;

	vty_out(vty, "enable%s", VTY_NEWLINE);
	vty_out(vty, "configure terminal%s", VTY_NEWLINE);

	int i = 0;
	struct cmd_node* node = NULL;
	for (; i < vector_active(cmdvec); i++) 
	{
		node = vector_slot(cmdvec, i);
		if (node && node->func)
		{
			node->func(vty);
		}
	}

	vty_out(vty, "end%s", VTY_NEWLINE);
	vty_close(vty);
}

int haa_warm_sync(struct vty* vty, int nReturn)
{
	if (nReturn != CMD_SUCCESS)
	{
		return CMD_SUCCESS;
	}

	struct vty_adapter* pAdapter = vty->slave_data;
	if (!pAdapter)
	{
		return CMD_SUCCESS;
	}

	char* cp = vty->buf;
	while (isspace(*cp))
	{
		cp++;
	}

	if (!cp || *cp == '\0')
	{
		return CMD_SUCCESS;
	}

	if (strncmp(cp, "show", 4) == 0
		|| strncmp(cp, "telnet", 6) == 0
		|| strncmp(cp, "who", 3) == 0)
	{
		return CMD_SUCCESS;
	}

	if (vty->node >= ENABLE_NODE && board_type == BOARDTYPE_IN)
	{
		while (pAdapter)
		{
			//SCLogInfo("slaveip: %s, port: %d\n", pAdapter->ip, pAdapter->port);
			//SCLogInfo("cmdline: %s\n", vty->buf);
			vty_adapter_run(vty, pAdapter);
			pAdapter = pAdapter->next;
		}
	}

	return CMD_SUCCESS;
}

struct vty_chain warm_sync_vty_chain = 
{
	.func = haa_warm_sync
};

int haa_vty_adapter_create(struct vty* vty)
{
	SlaveAddr* pSlaveAddr;
	struct vty_adapter* root = NULL;
	struct vty_adapter* prev = NULL;
	struct vty_adapter* adpt = NULL;

	if (g_nPrevState[0] == HA_STATE_ACT)
	{
		mutex_lock(&g_pHaAppControl->salveip_lock);
		for (int i = 0; i < vector_active(g_pHaAppControl->salveip_vector); i++)
		{
			pSlaveAddr = vector_lookup(g_pHaAppControl->salveip_vector, i);
			if (!pSlaveAddr)
			{
				continue;
			}

			SCLogInfo("slaveip: %s, port: %d\n", pSlaveAddr->ip, pSlaveAddr->nPort);
			for (int i = 0; i < 10; i++)
			{
				adpt = vty_adapter_init(NULL, pSlaveAddr->ip, pSlaveAddr->nPort);				
				if (adpt)
				{
					break;
				}
			}

			if (!root)
			{
				root = adpt;
			}
			else
			{
				prev->next = adpt;
			}

			prev = adpt;
		}
		mutex_unlock(&g_pHaAppControl->salveip_lock);
		vty->slave_data = root;
	}

	return 0;
}

int haa_vty_adapter_close(struct vty* vty)
{
	struct vty_adapter* next = NULL;
	struct vty_adapter* adpt = vty->slave_data;

	while (adpt)
	{
		SCLogInfo("haa_vty_adapter_close(): slaveip: %s, port: %d\n", adpt->ip, adpt->port);
		
		next = adpt->next;
		vty_adapter_deinit(adpt);
		adpt = next;
	}
	vty->slave_data = NULL;

	return 0;
}

void haa_vty_add_hook()
{
	vty_add_hook(VTY_CREATE_HOOK, haa_vty_adapter_create);
	vty_add_hook(VTY_CLOSE_HOOK, haa_vty_adapter_close);

	vty_chain_register(&warm_sync_vty_chain);
}

void slaveip_find_and_remove(HaAppControl* pHaAppControl, char* ip)
{
	int i = 0;
	SlaveAddr* pSlaveAddr = NULL;

	mutex_lock(&pHaAppControl->salveip_lock);
	for (; i < vector_active(pHaAppControl->salveip_vector); i++)
	{
		pSlaveAddr = vector_lookup(pHaAppControl->salveip_vector, i);
		if (pSlaveAddr && (!ip || !strcmp(pSlaveAddr->ip, ip)))
		{
			SCLogInfo("clear ip %s\n", pSlaveAddr->ip);
			vector_unset(pHaAppControl->salveip_vector, i);
			SCFree(pSlaveAddr);
			mutex_unlock(&pHaAppControl->salveip_lock);
			return;
		}
	}

	mutex_unlock(&pHaAppControl->salveip_lock);
}

int app_control_init()
{
	int nReturn = HA_SUCCESS;
	HaAppControl* pHaAppControl = (HaAppControl*)SCMalloc(sizeof(HaAppControl));
	if (NULL == pHaAppControl)
	{
		HA_LOG_ERROR("alloc memory for HA application control fail.\n");
		nReturn = -HA_ERROR_ERROR;
		return nReturn;
	}
	memset(pHaAppControl, 0, sizeof(HaAppControl));

	mutex_init(&pHaAppControl->handle_lock);
	INIT_LIST_HEAD(&pHaAppControl->handle_list);
	mutex_init(&pHaAppControl->salveip_lock);
	pHaAppControl->salveip_vector = vector_init(1);

	while (pHaAppControl->nSocketFd <= 0)
	{
		pHaAppControl->nSocketFd = ha_unix_sock_connect(HA_APP_MGR_PATH);
		if (pHaAppControl->nSocketFd > 0)
		{
			break;
		}
		usleep(10 * 1000);
	}

	if (pHaAppControl->nSocketFd < 0)
	{
		HA_LOG_ERROR("connect unix socket %s fail.\n", HA_APP_MGR_PATH);
		nReturn = -HA_ERROR_ERROR;
		goto FAIL;
	}

	HA_LOG_DEBUG("connect unix socket %s success.\n", HA_APP_MGR_PATH);

	pHaAppControl->base = thread_master_create();
	pHaAppControl->read_thread = thread_add_read(pHaAppControl->base, HaAgentRecv, pHaAppControl, pHaAppControl->nSocketFd);

	if (pthread_create(&pHaAppControl->pid, NULL, haa_ctrl_loopthread, pHaAppControl) < 0)
	{
		HA_LOG_ERROR("create HA application anent thread fail.\n");
		nReturn = -HA_ERROR_ERROR;
		goto FAIL1;
	}

	g_pHaAppControl = pHaAppControl;

	return nReturn;

FAIL1:
	thread_cancel(pHaAppControl->read_thread);
FAIL:
	SCFree(pHaAppControl);
	
	return nReturn;
}

static HaAppHandle* app_handle_get(HaAppControl* pHaAppControl, uint32_t dwAppModID)
{
	HaAppHandle* pHaAppHandle = NULL;

	mutex_lock(&pHaAppControl->handle_lock);
	list_for_each_entry(pHaAppHandle, &pHaAppControl->handle_list, node)
	{
		if (pHaAppHandle->dwAppModID == dwAppModID)
		{
			mutex_unlock(&pHaAppControl->handle_lock);
			return pHaAppHandle;
		}
	}
	mutex_unlock(&pHaAppControl->handle_lock);

	pHaAppHandle = (HaAppHandle*)SCMalloc(sizeof(HaAppHandle));
	if (NULL == pHaAppHandle)
	{
		return NULL;
	}

	memset(pHaAppHandle, 0, sizeof(HaAppHandle));
	pHaAppHandle->dwAppModID = dwAppModID;
	
	mutex_lock(&pHaAppControl->handle_lock);
	list_add(&pHaAppHandle->node, &pHaAppControl->handle_list);
	mutex_unlock(&pHaAppControl->handle_lock);

	return pHaAppHandle;
}

static HaAppHandle* app_handle_lookup(HaAppControl* pHaAppControl, uint32_t dwAppModID)
{
	HaAppHandle* pHaAppHandle = NULL;

	mutex_lock(&pHaAppControl->handle_lock);
	list_for_each_entry(pHaAppHandle, &pHaAppControl->handle_list, node)
	{
		if (pHaAppHandle->dwAppModID == dwAppModID)
		{
			mutex_unlock(&pHaAppControl->handle_lock);
			return pHaAppHandle;
		}
	}
	mutex_unlock(&pHaAppControl->handle_lock);

	return NULL;
}

int ha_unix_sock_connect(char* pPath)
{
	/* Make UNIX domain socket. */
	int nSocketFd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (nSocketFd < 0)
	{
		HA_LOG_ERROR("Cannot create unix stream socket: %s", strerror(errno));
		return -HA_ERROR_ERROR;
	}
	
	int nFlags = fcntl(nSocketFd, F_GETFL, 0);
	fcntl(nSocketFd, F_SETFL, nFlags | O_NONBLOCK);

	/* Make server socket. */
	struct sockaddr_un rServerAddr;
	memset(&rServerAddr, 0, sizeof(struct sockaddr_un));
	rServerAddr.sun_family = AF_UNIX;
	strncpy(rServerAddr.sun_path, pPath, strlen(pPath));
	
	int nDataLen = sizeof(rServerAddr.sun_family) + strlen(rServerAddr.sun_path);
	int nReturn = connect(nSocketFd, (struct sockaddr*)&rServerAddr, nDataLen);
	if (nReturn < 0)
	{
		HA_LOG_ERROR("Cannot connect path %s: %s", pPath, strerror(errno));
		close(nSocketFd);   /* Avoid sd leak. */
		return -HA_ERROR_ERROR;
	}
	
	return nSocketFd;
}

HaErrorCode HaAgentSend(HaAppControl* pHaAppControl, char* pData, int nDataLen)
{
	HaErrorCode nReturn = HA_SUCCESS;

	if (write(pHaAppControl->nSocketFd, pData, nDataLen) < 0)
	{
		return HA_ERROR_WRITE;
	}

	return nReturn;
}

static int HaAgentRecv(struct thread* t)
{
	SlaveAddr* pSlaveAddr = NULL;
	struct vty_adapter* pAdapter = NULL;
	
	HaAppMessageHead* pAppMessageHead = NULL;
	
	int nSocketFd = THREAD_FD(t);
	HaAppControl* pHaAppControl = (HaAppControl*)THREAD_ARG(t);
	pHaAppControl->read_thread = NULL;

	uint32_t nDataLen = 0;
	uint32_t nTotalLen = read(nSocketFd, pHaAppControl->chDataBuffer, HA_APP_MESSAGE_LEN_MAX);

	while (nDataLen < nTotalLen)
	{
		pHaAppControl->pRecvMsg = (struct HaAppMessage*)(pHaAppControl->chDataBuffer + nDataLen);
		pAppMessageHead = &pHaAppControl->pRecvMsg->rAppMessageHead;
		nDataLen += pAppMessageHead->nTotalLen;

		SCLogInfo("pAppMessageHead->nType: %d\n", pAppMessageHead->nType);

		switch (pAppMessageHead->nType)
		{
		case HA_APP_MESSAGE_TYPE_RESPONE:
			break;

		case HA_APP_MESSAGE_TYPE_NOTIFY:
			{
				/* is a event trap, call cb */
				HaAppHandle* pHaAppHandle = NULL;

				if (pAppMessageHead->nAppMsgID == HA_APP_DATA_SYNC)
				{
					pHaAppHandle = app_handle_lookup(g_pHaAppControl, pAppMessageHead->dwAppModID);
					if (pHaAppHandle && pHaAppHandle->HaSyncRcvCB)
					{
						pHaAppHandle->HaSyncRcvCB(pAppMessageHead->dwAppModID,
							pHaAppControl->chDataBuffer + HA_APP_MESSAGE_HEAD_LEN,
							pAppMessageHead->nTotalLen - HA_APP_MESSAGE_HEAD_LEN);
					}
				}
				else
				{
					HaEventMsg* pEventMsg = &pHaAppControl->pRecvMsg->u.rEventMsg;

					SCLogInfo("ha_agent event: %s\n", ha_event_to_str(pEventMsg->nHaEvent));
					
					list_for_each_entry(pHaAppHandle, &g_pHaAppControl->handle_list, node)
					{
						switch (pEventMsg->nHaEvent)
						{
						case HA_EVENT_GO_ACT:
							/* we running as active, read config from file */
							SCLogInfo("config_file: %s, config_default_dir: %s\n", config_file, config_default_dir);
							
							if (g_nPrevState[0] != HA_STATE_STB && g_nPrevState[0] != HA_STATE_ACT)
							{
								vty_read_config(config_file, config_default_dir);
							}
								
							g_nPrevState[1] = g_nPrevState[0];
							g_nPrevState[0] = HA_STATE_ACT;							
							break;

						case HA_EVENT_GO_STB:
							/* we run as standby, create vty socket server */
							SCLogInfo("GO_STB ip: %s, port: %d\n", pEventMsg->chData, (pHaAppHandle->dwAppModID & 0xffff));
							
							if (g_nPrevState[0] != HA_STATE_STB && g_nPrevState[0] != HA_STATE_ACT)
							{
								vty_read_config(config_file, config_default_dir);
							}

							if ((pHaAppHandle->dwAppModID & 0xffff))
							{
								//g_nServerFd = vty_serv_sock(pEventMsg->chData, pHaAppHandle->dwAppModID & 0xffff, NULL);
								pHaAppHandle->nVtyServerCreated = 1;
							}
							host_config_set(config_file);
							g_nPrevState[1] = g_nPrevState[0];
							g_nPrevState[0] = HA_STATE_STB;
							break;

						case HA_EVENT_STB_UP:
							/* start sync running config */
							pSlaveAddr = SCMalloc(sizeof(SlaveAddr));
							if (!pSlaveAddr)
							{
								break;
							}

							memset(pSlaveAddr, 0, sizeof(SlaveAddr));
							pSlaveAddr->nPort = (pHaAppHandle->dwAppModID & 0xffff);
							strncpy(pSlaveAddr->ip, pEventMsg->chData, sizeof(pSlaveAddr->ip));
							
							SCLogInfo("STB_UP IP: %s\n", pSlaveAddr->ip);
							
							mutex_lock(&g_pHaAppControl->salveip_lock);
							vector_set(g_pHaAppControl->salveip_vector, pSlaveAddr);
							mutex_unlock(&g_pHaAppControl->salveip_lock);

							if (g_nPrevState[1] == HA_STATE_STB)
							{
								break;
							}

							for (int i = 0; i < 100; i++)
							{
								pAdapter = vty_adapter_init(NULL, pSlaveAddr->ip, pSlaveAddr->nPort);
								//SCLogInfo("-------------pAdapter: %p, connect %s-------------\n", pAdapter, pSlaveAddr->ip);
								if (pAdapter)
								{
									haa_cold_sync(pAdapter->fd);
									vty_adapter_deinit(pAdapter);
									break;
								}
								usleep(50 * 1000);
							}
							break;

						case HA_EVENT_PEER_CONN_OK:
							/* now we finish sync running config, we will add to vty chain */
							break;

						case HA_EVENT_STB_DOWN:
							SCLogInfo("STB_DOWN ip: %s\n", pEventMsg->chData);
							slaveip_find_and_remove(g_pHaAppControl, pEventMsg->chData);
							break;

						case HA_EVENT_GO_OOS:
							//SCLogInfo("GO_OOS, close nServerFd %d\n", g_nServerFd);
							slaveip_find_and_remove(g_pHaAppControl, NULL);
							//vty_serv_cancel(g_nServerFd);
							break;

						default:
							break;
						}
						
						pHaAppHandle->HaEventCB(pEventMsg->nHaEvent, pHaAppHandle->pParam);
					}
				}
			}
		}
	}

	pHaAppControl->read_thread = thread_add_read(pHaAppControl->base, HaAgentRecv, pHaAppControl, nSocketFd);

	return 0;
}

static void* haa_ctrl_loopthread(void* args)
{	
	HaAppControl* pHaAppControl = (HaAppControl*)args;
	pHaAppControl->nFlag = 1;

	struct thread thread;
	while (thread_fetch(pHaAppControl->base, &thread)) 
	{
		thread_call(&thread);
	}
	SCLogInfo("APP control finish: %p", pHaAppControl);

	return NULL;
}

int haa_register(HaAppControl* pHaAppControl, uint32_t dwAppModID)
{
	HaAppMessage rAppMessage;

	rAppMessage.rAppMessageHead.nType = HA_APP_MESSAGE_TYPE_REQUEST;
	rAppMessage.rAppMessageHead.nAppMsgID = HA_APP_REGISTER;
	rAppMessage.rAppMessageHead.dwAppModID = dwAppModID;
	rAppMessage.rAppMessageHead.nTotalLen = HA_APP_MESSAGE_HEAD_LEN;
	int nDataLen = HA_APP_MESSAGE_HEAD_LEN;

	return HaAgentSend(pHaAppControl, (char*)&rAppMessage, nDataLen);
}

/**	APP register to HA.
	@param dwAppModID to indicate which Application will use HA function.
	@param nFlags bit0 to indicate this Application is last.
	@param pNotifCBF a event callback function to process
	@param pSyncRcvCBF a data sync function to process
	@param pParam customize parameters.
	@retrun HA error code.*/
HaErrorCode ha_app_register(uint32_t dwAppModID,
	uint32_t nFlags,
	ha_event_cb pNotifCBF,
	ha_sync_recv_cb pSyncRcvCBF,
	void* pParam)
{
	int nReturn;
	if (NULL == g_pHaAppControl)
	{
		nReturn = app_control_init();
		if (nReturn != HA_SUCCESS)
		{
			return nReturn;
		}
	}

	HaAppHandle* pHaAppHandle = app_handle_get(g_pHaAppControl, dwAppModID);
	pHaAppHandle->dwAppModID = dwAppModID;
	pHaAppHandle->HaEventCB = pNotifCBF;
	pHaAppHandle->HaSyncRcvCB = pSyncRcvCBF;
	pHaAppHandle->pParam = pParam;

	nReturn = haa_register(g_pHaAppControl, dwAppModID);
	if (nReturn != HA_SUCCESS && nReturn != HA_ERROR_EXIST)
	{
		HA_LOG_ERROR("Application register return %d", nReturn);
	}

	if (nFlags & 1)
	{
		ha_app_register_finish_notify();
	}

	return nReturn;
}

HaErrorCode ha_app_unregister(uint32_t dwAppModID)
{
	int nReturn = HA_ERROR_NOEXIST;
	if (NULL == g_pHaAppControl) 
	{
		return nReturn;
	}

	HaAppMessage rAppMessage;

	rAppMessage.rAppMessageHead.nType = HA_APP_MESSAGE_TYPE_REQUEST;
	rAppMessage.rAppMessageHead.nAppMsgID = HA_APP_UNREGISTER;
	rAppMessage.rAppMessageHead.dwAppModID = dwAppModID;
	rAppMessage.rAppMessageHead.nTotalLen = HA_APP_MESSAGE_HEAD_LEN;
	
	int nDataLen = HA_APP_MESSAGE_HEAD_LEN;
	nReturn = HaAgentSend(g_pHaAppControl, (char*)&rAppMessage, nDataLen);

	return nReturn;
}

void ha_app_register_finish_notify()
{
	sem_t* ha_mutex = sem_open(HA_SHM_SEMPHERE_NAM, O_CREAT, 0644, 1);
	if (ha_mutex == SEM_FAILED)
	{
		HA_LOG_ERROR("open semphere %s fail.\n", HA_SHM_SEMPHERE_NAM);
		sem_unlink(HA_SHM_SEMPHERE_NAM);
		return;
	}

	/* wait last register APP to post semphere */
	sem_post(ha_mutex);

	/* close and unlink semphere */
	sem_close(ha_mutex);
	sem_unlink(HA_SHM_SEMPHERE_NAM);

	return;
}

int ha_data_sync(uint32_t dwAppModID, const char* pDate, int nDataLen)
{
	int nTotalLen = HA_APP_MESSAGE_HEAD_LEN + nDataLen;	

	HaAppHandle* pHaAppHandle = app_handle_lookup(g_pHaAppControl, dwAppModID);
	if (!pHaAppHandle || nDataLen > HA_APP_MESSAGE_LEN_MAX)
	{
		return HA_ERROR_NOMEM;
	}

	HaAppMessage rAppMessage;

	rAppMessage.rAppMessageHead.nType = HA_APP_MESSAGE_TYPE_REQUEST;
	rAppMessage.rAppMessageHead.nAppMsgID = HA_APP_DATA_SYNC;
	rAppMessage.rAppMessageHead.dwAppModID = dwAppModID;
	rAppMessage.rAppMessageHead.nTotalLen = nTotalLen;
	memcpy(rAppMessage.u.chData, pDate, nDataLen);

	HaErrorCode nReturn = HaAgentSend(g_pHaAppControl, (char*)&rAppMessage, nTotalLen);

	return nReturn;
}

int have_ha()
{
	return !access(PATH_HA_PID, F_OK);
}