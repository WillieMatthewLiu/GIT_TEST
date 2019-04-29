
#include "app_common.h"
#include "usertable.h"

static int g_usertable_initok = 0;
static int g_usertable_autoid = 0;
static pthread_mutex_t g_usertable_lock;
static HashListTable *g_id_to_user = NULL;

struct ip_port
{
	uint32_t ip;
	uint16_t port;
	struct gap_user *user;
};

uint32_t usertable_hashlist_hash(HashListTable *tb, void *ptr, uint16_t sz)
{
	struct gap_user *user = ptr;
	return ((uint32_t)user->id) % tb->array_size;
}

char usertable_hashlist_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct gap_user *u1 = p1;
	struct gap_user *u2 = p2;
	return (u1->id == u2->id);
}

void usertable_hashlist_onfree(void *ptr)
{
	struct gap_user *user = ptr;
	if (user->name)
		SCFree(user->name);
	SCFree(user);
}

int usertable_init()
{
	int ret, ok = 0;
	do
	{
		ret = pthread_mutex_init(&g_usertable_lock, NULL);
		if (ret != 0)
			break;

		g_id_to_user = HashListTableInit(100, usertable_hashlist_hash, usertable_hashlist_compare, usertable_hashlist_onfree);
		if (g_id_to_user == NULL)
			break;

		ok = 1;
	} while (0);

	if (ok == 0)
	{
		usertable_free();
		return -1;
	}
	g_usertable_initok = 1;
	return 0;
}

struct gap_user* usertable_getbyid(uint32_t uid, int autoalloc)
{
	struct gap_user *usr = NULL;
	if (uid == 0)
		return NULL;

	pthread_mutex_lock(&g_usertable_lock);
	struct gap_user tmp; tmp.id = uid;
	usr = HashListTableLookup(g_id_to_user, &tmp, sizeof(&tmp));
	if (usr == NULL && autoalloc == 1)
	{
		usr = SCMalloc(sizeof(struct gap_user));
		if (usr != NULL)
		{
			memset(usr, 0, sizeof(*usr));
			usr->id = uid;
			HashListTableAdd(g_id_to_user, usr, sizeof(usr));
		}
	}
	pthread_mutex_unlock(&g_usertable_lock);
	return usr;
}

int usertable_free_user(struct gap_user *usr)
{
	int ret;

	pthread_mutex_lock(&g_usertable_lock);
	ret = HashListTableRemove(g_id_to_user, usr, sizeof(usr));
	pthread_mutex_unlock(&g_usertable_lock);
	return ret;
}

uint32_t usertable_generic_id()
{
	g_usertable_autoid++;
	return g_usertable_autoid;
}

int usertable_free()
{
	if (g_usertable_initok == 0)
		return 0;
	pthread_mutex_lock(&g_usertable_lock);
	{
		if (g_id_to_user != NULL)
			HashListTableFree(g_id_to_user);
		g_id_to_user = NULL;
	}
	pthread_mutex_unlock(&g_usertable_lock);

	pthread_mutex_destroy(&g_usertable_lock);
	return 0;
}
