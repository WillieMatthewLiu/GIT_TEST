#include "app_common.h"
#include "json-c.h"

jobj jobj_get_obj(jobj obj, const char *key)
{
	char *ctx, *member, *dupkey;
	jobj tmp = NULL;

	if (json_object_object_get_ex(obj, key, &tmp))
		return tmp;

	if (strchr(key, '.') == NULL)
		return NULL;

	dupkey = SCStrdup(key);
	if (dupkey == NULL)
		return NULL;

	for (member = strtok_s(dupkey, ".", &ctx); member != NULL; member = strtok_s(NULL, ".", &ctx))
	{
		int arrindex = -1;
		char *p = strchr(member, '[');
		if (p != NULL)
		{
			*p = 0;
			arrindex = atoi(p++);
		}

		if (!json_object_object_get_ex(obj, member, &obj))
			break;

		if (arrindex >= 0)
		{
			obj = json_object_array_get_idx(obj, atoi(p++));
			if (obj == NULL)
				break;
		}
	}
	SCFree(dupkey);
	return obj;
}

int jobj_set_obj(jobj obj, const char *key, jobj value)
{
	char *member, *dupkey;

	if (strchr(key, '.') == NULL)
	{
		json_object_object_add(obj, key, value);
		return 0;
	}

	member = dupkey = SCStrdup(key);
	if (dupkey == NULL)
		return -1;

	while (1)
	{
		char *dot = strchr(member, '.');
		if (dot == NULL)
			break;
		*dot = 0;

		jobj tmp = NULL;
		json_object_object_get_ex(obj, member, &tmp);

		if (tmp == NULL)
		{
			tmp = json_object_new_object();
			json_object_object_add(obj, member, tmp);
		}
		obj = tmp;

		member = dot + 1;
	}

	json_object_object_add(obj, member, value);
	SCFree(dupkey);
	return 0;
}

inline jobj jobj_load(const char *str)
{
    return json_tokener_parse(str);
}

inline const char *jobj_tostr(jobj obj)
{
    return json_object_to_json_string(obj);
}

inline void jobj_free(jobj obj)
{
    json_object_put(obj);
}

inline jobj jobj_new_obj()
{
    return json_object_new_object();
}

inline jobj jobj_new_arr()
{
    return json_object_new_array();
}

inline jobj jobj_new_str(const char *value)
{
    return json_object_new_string(value);
}

inline jobj jobj_new_int(int value)
{
    return json_object_new_int(value);
}

inline jobj jobj_new_int64(int64_t value)
{
    return json_object_new_int64(value);
}

inline jobj jobj_new_double(double value)
{
    return json_object_new_double(value);
}

inline jobj jobj_new_bool(json_bool value)
{
    return json_object_new_boolean(value);
}

inline int jarr_get_length(jarr arr)
{
    return json_object_array_length(arr);
}

inline int jarr_add_obj(jarr arr, jobj value)
{
    return json_object_array_add(arr, value);
}

inline int jarr_add_str(jarr arr, const char *value)
{
    return jarr_add_obj(arr, jobj_new_str(value));
}

inline int jarr_add_int(jarr arr, int value)
{
    return jarr_add_obj(arr, jobj_new_int(value));
}

inline int jarr_add_int64(jarr arr, int64_t value)
{
    return jarr_add_obj(arr, jobj_new_int64(value));
}

inline int jarr_add_double(jarr arr, double value)
{
    return jarr_add_obj(arr, jobj_new_double(value));
}

inline int jarr_add_bool(jarr arr, json_bool value)
{
    jarr_add_obj(arr, jobj_new_bool(value));
}

inline jobj jarr_get_obj(jarr arr, int i)
{
    return json_object_array_get_idx(arr, i);
}

inline const char* jarr_get_str(jarr arr, int i)
{
    return json_object_get_string(json_object_array_get_idx(arr, i));
}

inline int jarr_get_int(jarr arr, int i)
{
    return json_object_get_int(json_object_array_get_idx(arr, i));
}

inline int64_t jarr_get_int64(jarr arr, int i)
{
    return json_object_get_int64(json_object_array_get_idx(arr, i));
}

inline double jarr_get_double(jarr arr, int i)
{
    return json_object_get_double(json_object_array_get_idx(arr, i));
}

inline json_bool jarr_get_bool(jarr arr, int i)
{
    return json_object_get_boolean(json_object_array_get_idx(arr, i));
}

inline const char* jobj_get_str(jobj obj, const char *key)
{
    return json_object_get_string(jobj_get_obj(obj, key));
}

inline int jobj_get_int(jobj obj, const char *key)
{
    return json_object_get_int(jobj_get_obj(obj, key));
}

inline int64_t jobj_get_int64(jobj obj, const char *key)
{
    return json_object_get_int64(jobj_get_obj(obj, key));
}

inline double jobj_get_double(jobj obj, const char *key)
{
    return json_object_get_double(jobj_get_obj(obj, key));
}

inline json_bool jobj_get_bool(jobj obj, const char *key)
{
    return json_object_get_boolean(jobj_get_obj(obj, key));
}

inline int jobj_set_str(jobj obj, const char *key, const char *value)
{
    return jobj_set_obj(obj, key, json_object_new_string(value));
}

inline int jobj_set_int(jobj obj, const char *key, int value)
{
    return jobj_set_obj(obj, key, json_object_new_int(value));
}

inline int jobj_set_int64(jobj obj, const char *key, int64_t value)
{
    return jobj_set_obj(obj, key, json_object_new_int64(value));
}

inline int jobj_set_double(jobj obj, const char *key, double value)
{
    return jobj_set_obj(obj, key, json_object_new_double(value));
}

inline int jobj_set_bool(jobj obj, const char *key, json_bool value)
{
    return jobj_set_obj(obj, key, json_object_new_boolean(value));
}
