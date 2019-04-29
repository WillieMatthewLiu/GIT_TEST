#ifndef _RFC_H_
#define _RFC_H_
/********************************************************************************************
The RFC algorithm
  Classifying a packet can be viewed as mapping bits in the packet header to bits of
classID (an identifier denoting the rule, or action), where , , in a manner dictated
by the classifier rules. A simple and fast, but unrealistic, way of doing this mapping
might be to precompute the value of classID for each of the different packet header
values. This would yield the answer in one step (i.e., one memory access) but would
require too much memory. The main aim of RFC is to perform the same mapping but over
several stages. As shown in Figure 4.16, RFC performs this mapping recursively — in
each stage the algorithm performs a reduction, mapping one set of values to a smaller set.
************************************************************************************************/
#include "config.h"
#include "zebra.h"
#include "prefix.h"

#define MAX_RULE_NUM 0x10000


struct equivalence_class {
	unsigned int id;
	unsigned long *cbm;
};


#define RFC_RANGE_TYPE 0
struct rfc_range {
	unsigned short int start;
	unsigned short int end;
};

struct rfc_rule {
	struct prefix sip;
	struct prefix dip;
	struct rfc_range sport;
	struct rfc_range dport;
	struct rfc_range protocol;
	struct rfc_range ifindex;
	void *info;
};

typedef struct {
	unsigned int length; /* bitset length */
	unsigned long *bitset;
}BitSet;

typedef struct {
	BitSet *bs;
	unsigned int eq_id;
}BS_EQ_MAP;

#define MAX_PHASE0_CHUNKS 8
#define MAX_PHASE1_CHUNKS 2
#define MAX_USHORT_MASK 0xFFFF
typedef struct
{
	int ipaddress;
	int prefixe;
}EqIpPrefix;

typedef struct {
	unsigned short int *RFCTable[MAX_PHASE0_CHUNKS];
	vector CBMTable[MAX_PHASE0_CHUNKS];
	int Eq_ID[MAX_PHASE0_CHUNKS];
}Phase0;

typedef struct {
	unsigned short int *RFCTable[MAX_PHASE1_CHUNKS];
	vector CBMTable[MAX_PHASE1_CHUNKS];
	int Eq_ID[MAX_PHASE1_CHUNKS];
}Phase1;

typedef struct {
	int *RFCTable;
}Phase2;

struct RFC_table {
	Phase0 phase0;
	Phase1 phase1;
	Phase2 phase2;
};

/*
	RFC table init, used for init some global var.
*/
void RFC_table_init();

/* start rfc calculate */
int rfc_commit(struct rfc_rule *rule_list, unsigned int rule_size);

/* rfc match,  if unmatch, return the max table index */
int rfc_match(const unsigned int sip, const unsigned int dip,
	const unsigned short int sport, const unsigned short int dport,
	const unsigned short int protocol, const unsigned short int ifindex);

void dump_rfc_table(char *file);

#endif
