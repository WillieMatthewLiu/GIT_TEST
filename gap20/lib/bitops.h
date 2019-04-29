#ifndef _BITOPS_H
#define _BITOPS_H

#include <limits.h>

/* Defines */
#define BIT_PER_LONG	(CHAR_BIT * sizeof(unsigned long))
#define BIT_MASK(idx)	(1UL << ((idx) % BIT_PER_LONG))
#define BIT_WORD(idx)	((idx) / BIT_PER_LONG)

/* Helpers */
static inline void __set_bit(int idx, unsigned long *bmap)
{
	unsigned long mask = BIT_MASK(idx);
	unsigned long *p = ((unsigned long *)bmap) + BIT_WORD(idx);

	*p |= mask;
}

static inline void __clear_bit(int idx, unsigned long *bmap)
{
	unsigned long mask = BIT_MASK(idx);
	unsigned long *p = ((unsigned long *)bmap) + BIT_WORD(idx);

	*p &= ~mask;
}

static inline int __test_bit(int idx, unsigned long *bmap)
{
	unsigned long mask = BIT_MASK(idx);
	unsigned long *p = ((unsigned long *)bmap) + BIT_WORD(idx);

	return *p & mask;
}

/* Bits */
enum global_bits {
	LOG_CONSOLE_BIT = 0,
	DONT_FORK_BIT = 1,
	DUMP_CONF_BIT = 2,
	DONT_RELEASE_VRRP_BIT = 3,
	DONT_RELEASE_IPVS_BIT = 4,
	LOG_DETAIL_BIT = 5,
	DONT_RESPAWN_BIT = 6,
	RELEASE_VIPS_BIT = 7,
	MEM_ERR_DETECT_BIT = 8,
};

#endif

