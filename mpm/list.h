

#ifndef __LIST_H__
#define __LIST_H__

#ifdef __cplusplus
extern "C"{
#endif


typedef struct _list_node{
    struct _list_node *prev;
    struct _list_node *next;
}list_node;

#define member_of(t,m) \
    ((unsigned long long)(&(((t *)0)->m)))

#define list_entity(e, t, m)\
    (t *)(((unsigned long long)(e)) - member_of(t, m))

#define container_of(e, t, m) list_entity(e, t, m)


static inline void list_init(list_node *h){
    h->prev = h;
    h->next = h;
}

static inline void swlist_add(list_node *e, list_node *h){
    e->next = h->next;
    h->next->prev = e;
    h->next = e;
    e->prev = h;
}

static inline void list_insert(list_node *e, list_node *h){
    e->prev = h->prev;
    h->prev->next = e;
    h->prev = e;
    e->next = h;
}


static inline void list_del(list_node *e){
    e->prev->next = e->next;
    e->next->prev = e->prev;
}

static inline void list_del_init(list_node *e){
    list_del(e);
    list_init(e);
}


#define list_for_each(e, h)\
    for( (e) = (h)->next; (e) != (h); (e) = (e)->next)

//for delete
#define list_for_safe_each(e, s, h)\
    for( (e)=(h)->next,(s)=(e)->next; (e) != (h); (e) = (s), (s)=(s)->next)

#define swlist_empty(h) \
    ((h)->next == (h) && (h)->prev == (h))


#ifdef __cplusplus
}
#endif
#endif
