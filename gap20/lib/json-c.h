#ifndef __JSON_C_H__
#define __JSON_C_H__
#include <json-c/json.h>
#include <json-c/bits.h>

#define NAME_KEY "name"
#define ALIAS_KEY "alias"
#define IP_KEY "ip"
#define MASK_KEY "mask"
#define LABEL_KEY "label"
#define VIPS_KEY "vips"
#define STATE_KEY "state"
#define PSTATE_KEY "pstate"
#define FLAGS_KEY "flags"
#define MEMBERS_KEY "members"
#define MAC_KEY  "mac"
#define MODE_KEY "mode"
#define MODESTR_KEY "modestr"
#define GATEWAY_KEY "gateway"


#define S2J_SET_int_ELEMENT(json_obj, src_struct, type, element) \
    json_object_object_add(json_obj, #element, json_object_new_int(src_struct->element))

#define S2J_SET_int64_ELEMENT(json_obj, src_struct, type, element) \
    json_object_object_add(json_obj, #element, json_object_new_int64(src_struct->element))

#define S2J_SET_double_ELEMENT(json_obj, src_struct, type, element) \
    json_object_object_add(json_obj, #element, json_object_new_double(src_struct->element))

#define S2J_SET_string_ELEMENT(json_obj, src_struct, type, element) \
    json_object_object_add(json_obj, #element, json_object_new_string(src_struct->element))

#define S2J_SET_BASIC_ELEMENT(json_obj, src_struct, type, element) \
    S2J_SET_##type##_ELEMENT(json_obj, src_struct, type, element)


#define S2J_SET_STRING(json_obj, key, str) \
    json_object_object_add(json_obj, key, json_object_new_string(str))

#define S2J_SET_ARRAY(json_obj, element) \
    json_object_array_add(json_obj, element)

#define JSON_FORMAT_STR(json_obj) \
    json_object_to_json_string(json_obj)

#define JSON_FORMAT_STR_PLAIN(json_obj) \
    json_object_to_json_string_ext(json_obj, 0)
#endif

typedef struct json_object* jobj;
typedef struct json_object* jarr;

jobj jobj_get_obj(jobj obj, const char *key);
int jobj_set_obj(jobj obj, const char *key, jobj value);

jobj jobj_load(const char *str);
const char *jobj_tostr(jobj obj);
void jobj_free(jobj obj);

jobj jobj_new_obj();
jobj jobj_new_arr();
jobj jobj_new_str(const char *value);

jobj jobj_new_int(int value);
jobj jobj_new_int64(int64_t value);
jobj jobj_new_double(double value);
jobj jobj_new_bool(json_bool value);

int jarr_get_length(jarr arr);
int jarr_add_obj(jarr arr, jobj value);
int jarr_add_str(jarr arr, const char *value);

int jarr_add_int(jarr arr, int value);
int jarr_add_int64(jarr arr, int64_t value);
int jarr_add_double(jarr arr, double value);
int jarr_add_bool(jarr arr, json_bool value);

jobj jarr_get_obj(jarr arr, int i);
const char* jarr_get_str(jarr arr, int i);
int jarr_get_int(jarr arr, int i);
int64_t jarr_get_int64(jarr arr, int i);
double jarr_get_double(jarr arr, int i);
json_bool jarr_get_bool(jarr arr, int i);

const char* jobj_get_str(jobj obj, const char *key);
int jobj_get_int(jobj obj, const char *key);
int64_t jobj_get_int64(jobj obj, const char *key);
double jobj_get_double(jobj obj, const char *key);
json_bool jobj_get_bool(jobj obj, const char *key);

int jobj_set_str(jobj obj, const char *key, const char *value);
int jobj_set_int(jobj obj, const char *key, int value);
int jobj_set_int64(jobj obj, const char *key, int64_t value);
int jobj_set_double(jobj obj, const char *key, double value);
int jobj_set_bool(jobj obj, const char *key, json_bool value);


