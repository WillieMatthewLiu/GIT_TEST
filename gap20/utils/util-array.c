
#include "util-array.h"
#include "app_common.h"

// copy from zebra::vector

void array_test()
{
	struct array * arr = array_init(0);
	for (int i = 0; i < 100; i++)
		array_add(arr, (void*)i);
	int cnt = array_count(arr); assert(cnt == 100);

	array_removeat(arr, 0);
	array_removeat(arr, 1);
	array_removeat(arr, 3);
	array_removeat(arr, 2);
	array_removeat(arr, 1);
	array_removeat(arr, 0);
	cnt = array_count(arr); assert(cnt == 94);
	for (int i = 0; i < cnt; i++)
	{
		void *p = array_getat(arr, i);
		assert(p == (void*)(i + 6));
		//SCLogInfo("%d", p);
	}

	struct array * arr1 = array_clone(arr);
	int n = 6;
	while (1)
	{
		void *p = array_removeat(arr1, 0);
		if (p == NULL)
			break;
		assert(p == (void*)(n++));
		//SCLogInfo("%d", p);
	}

	array_free(arr);
	array_free(arr1);
}

struct array *
	array_init(unsigned int size)
{
	struct array * arr = SCMalloc(sizeof(struct array));
	if (arr == NULL)
		return NULL;

	if (size == 0)
		size = 1;

	arr->alloced = size;
	arr->active = 0;
	arr->index = SCMalloc(sizeof(void *) * size);
	if (arr->index == NULL)
	{
		SCFree(arr);
		return NULL;
	}
	return arr;
}

void
array_free(struct array * arr)
{
	SCFree(arr->index);
	SCFree(arr);
}

struct array *
	array_clone(struct array * arr)
{
	unsigned int size;
	struct array * ret = SCMalloc(sizeof(struct array));
	if (ret == NULL)
		return NULL;

	ret->active = arr->active;
	ret->alloced = arr->alloced;

	size = sizeof(void *) * (arr->alloced);
	ret->index = SCMalloc(size);
	if (ret->index == NULL)
	{
		SCFree(ret);
		return NULL;
	}
	memcpy(ret->index, arr->index, size);

	return ret;
}

void
array_ensure(struct array * arr, unsigned int num)
{
	if (arr->alloced > num)
		return;

	arr->index = SCRealloc(arr->index, sizeof(void *) * (arr->alloced * 2));
	arr->alloced *= 2;

	if (arr->alloced <= num)
		array_ensure(arr, num);
}

int
array_add(struct array * arr, void *val)
{
	array_ensure(arr, arr->active);
	arr->index[arr->active] = val;
	arr->active++;
	return arr->active;
}

int
array_setat(struct array * arr, unsigned int i, void *val)
{
	array_ensure(arr, i);

	arr->index[i] = val;

	if (arr->active <= i)
		arr->active = i + 1;

	return i;
}

void *
array_getat(struct array * arr, unsigned int i)
{
	if (i >= arr->active)
		return NULL;
	return arr->index[i];
}
void **
array_getdata(struct array * arr)
{
	return arr->index;
}

void*
array_removeat(struct array * arr, unsigned int i)
{
	if (i >= arr->active)
		return NULL;
	void *ret = arr->index[i];
	memmove(arr->index + i, arr->index + i + 1, sizeof(void*)*(arr->active - i - 1));
	arr->active--;
	return ret;
}

int
array_count(struct array * v)
{
	return v->active;
}

int
array_find(struct array * arr, void *val)
{
	for (int i = 0; i < (int)arr->active; i++)
	{
		if (arr->index[i] == val)
			return i;
	}
	return -1;
}

int
array_find_and_remove(struct array * arr, void *val)
{
	int n = array_find(arr, val);
	if (n == -1)
		return -1;
	if (array_removeat(arr, n) != NULL)
		return 0;
	return -1;
}
