#pragma once

struct gap_user
{
	uint32_t id;	// id
	char *name;		// 用户名
	char key[32];	// 密钥
};

int usertable_init();
int usertable_free();

// 通过ID获取对应的gap_user，autoalloc=1表示如果ID不存在则创建一个新的，并返回
struct gap_user* usertable_getbyid(uint32_t uid, int autoalloc);
int usertable_free_user(struct gap_user *usr);

// 生成一个ID
uint32_t usertable_generic_id();
