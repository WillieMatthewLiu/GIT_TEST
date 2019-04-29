#include "app_common.h"
#include "card_route.h"

static char g_netdev[32];

unsigned int g_mask[32] = {
	0x80000000,
	0xc0000000,
	0xe0000000,
	0xf0000000,

	0xf8000000,
	0xfc000000,
	0xfe000000,
	0xff000000,

	0xff800000,
	0xffc00000,
	0xffe00000,
	0xfff00000,

	0xfff80000,
	0xfffc0000,
	0xfffe0000,
	0xffff0000,

	0xffff8000,
	0xffffc000,
	0xffffe000,
	0xfffff000,

	0xfffff800,
	0xfffffc00,
	0xfffffe00,
	0xffffff00,

	0xffffff80,
	0xffffffc0,
	0xffffffe0,
	0xfffffff0,

	0xfffffff8,
	0xfffffffc,
	0xfffffffe,
	0xffffffff
};

void space_to_zero(char *data, int len)
{
	int i;
	if(!data)
		return;
	for(i = 0; i < len; i++)
	{
		if(data[i] == ' ')
			data[i] = '\0';
	}
}

void zero_to_space(char *data, int len)
{
	int i;
	if(!data)
		return;
	for(i = 0; i < len; i++)
	{
		if(data[i] == '\0')
			data[i] = ' ';
	}
}

void space_to_underline(char *data, int len)
{
	int i;
	if(!data)
		return;
	for(i = 0; i < len; i++)
	{
		if(data[i] == ' ')
			data[i] = '_';
	}
	data[i] = '\0';
}

void underline_to_zero(char *data, int len)
{
	int i;
	if(!data)
		return;
	for(i = 0; i < len; i++)
	{
		if(data[i] == '_')
			data[i] = '\0';
	}
	data[i] = '\0';
}

void zero_to_underline(char *data, int len)
{
	int i;
	if(!data)
		return;
	for(i = 0; i < len; i++)
	{
		if(data[i] == '\0')
			data[i] = '_';
	}
}

uint32_t hashlist_route_hash(HashListTable *tb, void *ptr, uint16_t aa)
{
	struct route_node *s = ptr;
	return (uint32_t)((s->ip >> (32 - s->mask_bits)) % tb->array_size);
}

char hashlist_route_compare(void *p1, uint16_t sz1, void *p2, uint16_t sz2)
{
	struct route_node *s1 = p1;
	struct route_node *s2 = p2;
	int mask1 = s1->mask_bits;
	int mask2 = s2->mask_bits;
	
	return (mask1 == mask2 && (s1->ip & g_mask[mask1 - 1]) == (s2->ip & g_mask[mask2 - 1]));
}

void hashlist_route_onfree(void *ptr)
{
	struct route_node *route = ptr;
	SCFree(route);
}

struct route_node *parse_route_node(char *str)
{
	char *s = str;
	char *mark = NULL;
	unsigned int ip = 0;
	int mask_bits = 0;
	struct route_node *route = NULL;

	while(*s != '\0')
	{
		if(*s == '/')
			break;
		s++;
	}
	
	if(*s != '\0')
	{
		mark = s;
		*s++ = '\0';
		if(*s == '\0')
		{
			*mark = '/';
			SCLogError( "route string: %s error!\n", str);
			return NULL;
		}
		
		while(*s != '\0')
		{
			if(*s < '0' || *s > '9')
			{
				*mark = '/';
				SCLogError( "route string: %s error!\n", str);
				return NULL;
			}
			mask_bits = mask_bits*10 + *s - '0';
			s++;
		}

		if(mask_bits > 32)
		{
			*mark = '/';
			SCLogError( "route string: %s error!\n", str);
			return NULL;
		}
	}
	else
	{
		mask_bits = 32;
	}

	ip = inet_addr(str);
	if(ip == INADDR_NONE)
	{
		SCLogError( "route string: %s error!\n", str);
		return NULL;
	}

	if(mark)
		*mark = '/';
	route = SCMalloc(sizeof(struct route_node));
	if(route == NULL)
	{
		SCLogError( "route node alloc error!");
		return NULL;
	}
	route->ip = htonl(ip);
	route->mask_bits = mask_bits;

	return route;
}

HashListTable* route_hash_init(void)
{
	HashListTable *route = NULL;
	route = HashListTableInit(256, hashlist_route_hash, hashlist_route_compare, hashlist_route_onfree);
	return route;
}

void clear_routes(HashListTable **routes)
{
	int i;
	for(i = 31; i >= 0; i--)
	{
		if(routes[i])
			HashListTableFree(routes[i]);
		routes[i] = NULL;
	}
}

void add_routes(HashListTable **routes, char *routestr, int length, char *netdev)
{
	char *str = NULL;
	struct route_node *route = NULL;
	int len = 0;
	char cmd[96] = {0};
	struct in_addr routeip, netmask;

	if(!routes)
		return;
	
	clear_routes(routes);
	
	if(!routestr)
		return;
	
	memset(g_netdev, 0, sizeof(g_netdev));
	strcpy(g_netdev, netdev);
	space_to_zero(routestr, length);

	while(len < length)
	{
		str = routestr + len;
		len += (strlen(str) + 1);
		route = parse_route_node(str);
		if(route == NULL)
			SCLogError( "route string: %s error!\n", str);
		
		if(route)
		{
			if(!routes[route->mask_bits - 1])
			{
				routes[route->mask_bits - 1] = route_hash_init();
			}
			else
			{
				if(HashListTableLookup(routes[route->mask_bits - 1], route, sizeof(route)))
				{
					SCFree(route);
					continue;
				}
			}
			
			HashListTableAdd(routes[route->mask_bits - 1], route, sizeof(route));
			//printf("add_routes: ip = %08x, mask_bits = %d\n", route->ip, route->mask_bits);
			memset(cmd, 0, sizeof(cmd));
			routeip.s_addr = htonl(route->ip);
			netmask.s_addr = htonl(g_mask[route->mask_bits - 1]);
			snprintf(cmd, sizeof(cmd), "route add -net %s", inet_ntoa(routeip));
			snprintf(cmd + strlen(cmd), sizeof(cmd) - strlen(cmd), " netmask %s dev %s", inet_ntoa(netmask), netdev);
			if(system(cmd) == -1)
				SCLogError( "system(\"%s\") error!\n", cmd);
		}
	}

    zero_to_space(routestr, length);
}

/*
*ip mask be local byte order
*/
void add_route(HashListTable **routes, unsigned int ip, int mask_bits)
{
	struct route_node *route;

	if(mask_bits > 32)
	{
		SCLogError( "mask_bits: %d error!\n", mask_bits);
		return;
	}

	route = SCMalloc(sizeof(struct route_node));
	if(route == NULL)
	{
		SCLogError( "route node alloc error!");
		return;
	}
	route->ip = ip;
	route->mask_bits = mask_bits;
	if(!routes[mask_bits - 1])
	{
		routes[mask_bits - 1] = route_hash_init();
	}
	else
	{
		if(HashListTableLookup(routes[mask_bits - 1], route, sizeof(route)))
			return;
	}

	HashListTableAdd(routes[mask_bits - 1], route, sizeof(route));
}

/*
*ip: Local byte order
*/
struct route_node * find_route(HashListTable **routes, unsigned int ip)
{
	int i;
	struct route_node *route = NULL;
	struct route_node temp;

	for(i = 31; i >= 0; i--)
	{
		if(!routes[i])
			continue;
		
		temp.ip = ip;
		temp.mask_bits = i + 1;
		route = HashListTableLookup(routes[i], &temp, sizeof(&temp));
		if(route)
			break;
	}

	return route;
}

