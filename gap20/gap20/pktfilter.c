
#include "app_common.h"
#include "pktfilter.h"

struct packet_filter* g_filters[_SVR_ID_COUNT + 1] = { 0 };

int pktfilter_reg(struct packet_filter *flt)
{
	if (flt == NULL)
		return -1;
	if (g_filters[flt->svrid] != NULL)
		return -1;
	g_filters[flt->svrid] = flt;
	return 0;
}

int pktfilter_unreg(struct packet_filter *flt)
{
	if (flt == NULL)
		return -1;
	g_filters[flt->svrid] = NULL;
	return 0;
}

int pktfilter_init()
{
	for (int i = 0; i < _SVR_ID_COUNT; i++)
	{
		if (g_filters[i] != NULL)
		{
			int ret = g_filters[i]->initcb();
			if (ret != 0)
			{
				SCLogInfo("filter: %s init ret: %d", g_filters[i]->name, ret);
				return ret;
			}
		}
	}
	return 0;
}

void pktfilter_exit()
{
	for (int i = 0; i < _SVR_ID_COUNT; i++)
	{
		if (g_filters[i] != NULL)
			g_filters[i]->exitcb();
	}
}

struct packet_filter* pktfilter_get(enum SVR_ID id)
{
	return g_filters[id];
}
