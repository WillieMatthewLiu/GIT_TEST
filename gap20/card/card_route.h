#ifndef _CARD_ROUTE_H_
#define _CARD_ROUTE_H_


struct route_node 
{
	unsigned int ip;
	int mask_bits;
};

void space_to_zero(char *data, int len);
void zero_to_space(char *data, int len);
void space_to_underline(char *data, int len);
void underline_to_zero(char *data, int len);
void zero_to_underline(char *data, int len);
//HashListTable* route_hash_init(void);
struct route_node *parse_route_node(char *str);
void add_routes(HashListTable **routes, char *routestr, int length, char *netdev);
void add_route(HashListTable **routes, unsigned int ip, int mask_bits);
struct route_node * find_route(HashListTable **routes, unsigned int ip);
void clear_routes(HashListTable **routes);

#endif
