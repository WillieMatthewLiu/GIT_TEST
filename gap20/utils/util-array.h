#pragma once

struct array
{
	unsigned int active;
	unsigned int alloced;
	void **index;
};

#define array_slot(A,I)  ((A)->index[(I)])
#define array_active(A) ((A)->active)

extern struct array* array_init(unsigned int size);
extern void array_ensure(struct array *arr, unsigned int num);
extern int array_add(struct array *arr, void *val);
void* array_getat(struct array *arr, unsigned int i);
extern int array_setat(struct array *arr, unsigned int i, void *val);
void** array_getdata(struct array *arr);
extern void* array_removeat(struct array *arr, unsigned int i);
extern int array_count(struct array *arr);
int array_find(struct array *arr, void *val);
int array_find_and_remove(struct array *arr, void *val);
extern void array_free(struct array *arr);
extern struct array* array_clone(struct array *arr);

extern void array_test();

