#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#include "app_common.h"
#include "vector.h"
#include "hash.h"

#include "bitops.h"
#include "util-mem.h"

#include "rfc.h"
/**************************************************************
common reduction.
Chunk0--|
			 |--Chunk8----|
Chunk1--|                   |
								 |----Chunk12---|
Chunk2--|                   |                      |
			 |--Chunk9----|                      |
Chunk3--|                                           |
														 |-------Chunk14
Chunk4--|                                           |
			 |--Chunk10---|                      |
Chunk5--|                   |                      |
								 |----Chunk13---|
Chunk6--|                   |
			 |--Chunk11---|
Chunk7--|

|Phase 0 |    Phase 1     |     Phase 2      | phase 3

we want use this reduction:

SIP_H -->|
DIP_L -->|
			 |----chunk8 --->|
SPORT ->|                        |
PROTO-->|                       |
									 |-----chunk10
SIP_L -->|                       |
DIP_H-->|                        |
			 |----chunk9--->|
DPORT-->|
IFIDX -->|
*******************************************************************/

/***********************************************************************************************/
/* Phase 0, Chunk j of width b bits*/
//for each rule rl in the classifier
//begin
//  project the ith component of rl onto the number line , marking the start and end points of
//  each of its constituent intervals.
//endfor
/* Now scan through the number line looking for distinct equivalence classes */
//bmp := 0; /* all bits of bmp are initialised to '0'*/
//for n in 0..2b-1
//begin
//  if (any rule starts or ends at n)
//  begin
//      update bmp;
//      if (bmp not seen earlier)
//      begin
//          eq := new_equivalence_class();
//          eq->cbm := bmp;
//      endif
//  endif
//  else eq := the equivalence class whose cbm is bmp;
//  table_0_j[n] = eq->ID; /* fill ID in the rfc table*/
//endfor
/**************************************************************************************************/

/*************************************************************************************************/
/* Assume that chunk i is formed by combining m distinct chunks c1, c2, ..., cm of phases p1,p2, ...,
pm where p1, p2, ..., pm < j */
//indx := 0; /* indx runs through all the entries of the RFC table, table_j_i */
//listEqs := nil;
//for each CES, c1eq, of chunk c1
//  for each CES, c2eq, of chunk c2
//      ........
//  for each CES, cmeq of chunk cm
//  begin
//      intersectedBmp := c1eq->cbm & c2eq->cbm & ... & cmeq->cbm;/* bitwise ANDing */
//      neweq := searchList(listEqs, intersectedBmp);
//      if (not found in listEqs)
//      begin
/* create a new equivalence class */
//          neweq := new_Equivalence_Class();
//          neweq->cbm := bmp;
//          add neweq to listEqs;
//      endif
/* Fill up the relevant RFC table contents.*/
//  table_j_i[indx] := neweq->ID;
//  indx++;
//endfor
/****************************************************************************************************/



#define SIP_H_IDX 0
#define SIP_L_IDX 1
#define DIP_H_IDX 2
#define DIP_L_IDX 3
#define SPORT_IDX 4
#define DPORT_IDX 5
#define PROTO_IDX 6
#define IFIDX_IDX 7
#define MAX_IDX 8

#define MAX_CHUNK_SIZE 0x10000

#define ALIGN_ULONG(sz) ALIGN(sz, sizeof(unsigned long))

static int _rfc_table_idx = 0;
static struct RFC_table _rfc_table[2] = {};
static struct RFC_table *_current_use_table = _rfc_table;

/* reduction sequence */
static int C1[2][4] = {
	{SIP_H_IDX, DIP_L_IDX, SPORT_IDX, PROTO_IDX}, /* Phase1 chunk0 */
	{SIP_L_IDX, DIP_H_IDX, DPORT_IDX, IFIDX_IDX} /* Phase1 chunk2 */
};

static inline EqIpPrefix* new_EqIpPrefix()
{
	EqIpPrefix *ep = SCMalloc(sizeof(EqIpPrefix));
	if (NULL == ep) {
		return NULL;
	}
	memset(ep, 0, sizeof(EqIpPrefix));

	return ep;
}

static inline void free_EqlpPrefix(EqIpPrefix *ep)
{
	SCFree(ep);
	return;
}

static inline BitSet* BitSet_new(int bitlength)
{
	BitSet *bs;

	bitlength = ALIGN(bitlength, sizeof(unsigned long));
	bs = SCMalloc(sizeof(BitSet));
	if (NULL == bs)
	{
		return NULL;
	}

	memset(bs, 0, sizeof(BitSet));

	bs->bitset = SCMalloc(bitlength / sizeof(unsigned long));
	if (NULL == bs->bitset)
	{
		SCFree(bs);
		return NULL;
	}
	for (int i = 0; i < bitlength / sizeof(unsigned long); i++)
		bs->bitset[i] = 0;
	bs->length = bitlength;

	return bs;
}

static inline void BitSet_free(BitSet *bs)
{
	SCFree(bs->bitset);
	SCFree(bs);
}

/*
	Returns the "logical size" of this BitSet: the index of the highest set bit in the BitSet plus one.
*/
static inline int BitSet_length(BitSet *bs)
{
	int ret = bs->length;

	for (; ret > 0; ) {
		if (__test_bit(--ret, bs->bitset))
			return ret + 1;
	}

	return ret;
}

static inline void BitSet_set(int indx, BitSet *bs)
{
	__set_bit(indx, bs->bitset);
}

static inline void BitSet_or(BitSet *bs1, BitSet *bs2)
{
	for (int i = 0;
		(i < bs1->length / sizeof(unsigned long)) && (i < bs2->length / sizeof(unsigned long));
		i++)
	{
		bs1->bitset[i] |= bs2->bitset[i];
	}
}

static inline void BitSet_and(BitSet *bs1, BitSet *bs2)
{
	for (int i = 0;
		(i < bs1->length / sizeof(unsigned long)) && (i < bs2->length / sizeof(unsigned long));
		i++)
	{
		bs1->bitset[i] &= bs2->bitset[i];
	}
}

static inline void BitSet_clear(BitSet *bs)
{
	for (int i = 0; i < bs->length / sizeof(unsigned long); i++)
		bs->bitset[i] = 0;
}

static void * BitSet_copy(void *p)
{
	BitSet *bs = (BitSet *)p;
	BitSet *nbs = BitSet_new(bs->length);

	for (int i = 0; i < bs->length / sizeof(unsigned long); i++)
		nbs->bitset[i] = bs->bitset[i];

	return nbs;
}

void BitSet_print(BitSet *bs) {
	for (int i = bs->length - 1; i >= 0; i--) {
		fprintf(stdout, "%d", __test_bit(i, bs->bitset) ? 1 : 0);
	}
	fprintf(stdout, " ");
}

static unsigned int BitSet_hash_key(void *p)
{
	unsigned long ret = 0;
	BitSet *bs = (BitSet *)p;

	for (int i = 0; i < sizeof(*bs->bitset); i++)
	{
		ret ^= bs->bitset[i];
	}
	return (ret >> 32) ^ (ret & 0xFFFFFFF);
}

/* if p1 equals p2, return 1, else return 0 */
static int BitSet_hash_cmp(const void *p1, const void *p2)
{
	BitSet *bs1 = (BitSet *)p1;
	BitSet *bs2 = (BitSet *)p2;

	if (bs1->length != bs2->length)
		return 0;

	for (int i = 0; i < bs1->length / sizeof(unsigned long); i++)
	{
		if (bs1->bitset[i] != bs2->bitset[i])
			return 0;
	}
	return 1;
}

void BitSet_hash_free(void *p)
{
	BitSet *bs = (BitSet *)p;
	BitSet_free(bs);
}

static unsigned int BS_EQ_MAP_key(void *p)
{
	BS_EQ_MAP *be = (BS_EQ_MAP *)p;

	return BitSet_hash_key(be->bs);
}

static int BS_EQ_MAP_cmp(const void *p1, const void *p2)
{
	BS_EQ_MAP *be1, *be2;

	be1 = (BS_EQ_MAP *)p1;
	be2 = (BS_EQ_MAP *)p2;

	return BitSet_hash_cmp(be1->bs, be2->bs);
}

static void * BS_EQ_MAP_copy(void *p)
{
	BS_EQ_MAP *be = (BS_EQ_MAP *)p;
	BS_EQ_MAP *nbe = SCMalloc(sizeof(BS_EQ_MAP));

	nbe->bs = BitSet_copy(be->bs);
	nbe->eq_id = be->eq_id;

	return nbe;
}

static void BS_EQ_MAP_free(void *p)
{
	BS_EQ_MAP *be = (BS_EQ_MAP *)p;
	BitSet_free(be->bs);
	SCFree(be);
}

static int
CreatePhase0_RFCTable(int Eq_Id, unsigned short int * RFCTable,
	int Input_IP, int Input_Prefix, int ChunkBits,
	vector TempEqIpPrefix, int RuleCount, int RuleNo, vector CBM)
{
	int j, entrys;
	if (Input_Prefix != 0) {
		if (RFCTable[Input_IP] == 0)
		{
			RFCTable[Input_IP] = ++Eq_Id;
			EqIpPrefix *StoreThis = new_EqIpPrefix();
			StoreThis->ipaddress = Input_IP;
			StoreThis->prefixe = Input_Prefix;
			vector_set(TempEqIpPrefix, StoreThis);
			BitSet *Temp = BitSet_new(RuleCount);
			BitSet_set(RuleCount - RuleNo - 1, Temp);
			vector_set_index(CBM, Eq_Id, Temp);

			//for remanining entrys if any
			entrys = (int)pow(2, (ChunkBits - Input_Prefix));
			for (int j = entrys; j > 1; j--)
			{
				if (RFCTable[Input_IP + j - 1] == 0)
					RFCTable[Input_IP + j - 1] = Eq_Id;
				else
				{
					//CBM.get(RFCTable[Input_IP + j - 1]).or(CBM.get(Eq_Id));
					BitSet *bs = vector_slot(CBM, RFCTable[Input_IP + j - 1]);
					BitSet *ebs = vector_slot(CBM, Eq_Id);
					BitSet_or(bs, ebs);
				}
			}
		}
		else
		{
			/*for more specific IP address entry in RFC table. Subset of IP@ should not be given same eq_id as that of
			its superset */
			EqIpPrefix *ep = vector_slot(TempEqIpPrefix, RFCTable[Input_IP] - 1);
			if ((ep->ipaddress != Input_IP) &&
				(ep->prefixe != Input_Prefix))
			{
				BitSet *cbmt;
				BitSet *Temp = BitSet_new(RuleCount);
				BitSet_set(RuleCount - RuleNo - 1, Temp);

				cbmt = vector_slot(CBM, RFCTable[Input_IP]);
				BitSet_or(Temp, cbmt);
				RFCTable[Input_IP] = ++Eq_Id; //storing at updated eq_id
				vector_set_index(CBM, Eq_Id, Temp->bitset);

				EqIpPrefix *StoreThis = new_EqIpPrefix();
				StoreThis->ipaddress = Input_IP;
				StoreThis->prefixe = Input_Prefix;
				vector_set(TempEqIpPrefix, StoreThis);

				//For remaining entrys in RFCtable
				entrys = (int)pow(2, (ChunkBits - Input_Prefix));
				for (j = entrys; j > 1; j--)
				{
					if (RFCTable[Input_IP + j - 1] == 0)
						RFCTable[Input_IP + j - 1] = Eq_Id;
					else
					{
						BitSet *bs = vector_slot(CBM, RFCTable[Input_IP + j - 1]);
						BitSet *ebs = vector_slot(CBM, Eq_Id);
						BitSet_or(bs, ebs);
					}
				}
			}
			else {
				BitSet *bs = vector_slot(CBM, RFCTable[Input_IP]);
				BitSet_set(RuleCount - RuleNo - 1, bs);
			}

		}
	}
	else {
		BitSet *bs = vector_slot(CBM, 0);
		BitSet_set(RuleCount - RuleNo - 1, bs);
	}
	return Eq_Id;

}

static int
CreateRFCTable_Range(int Eq_Id, unsigned short int  *RFCTable,
	int start, int end, vector TempEqIpPrefix,
	int RuleCount, int RuleNo, vector CBM)
{
	int j;
	if (start != 0 && end != 65535) {

		if (RFCTable[start] == 0)
		{
			RFCTable[start] = ++Eq_Id;
			EqIpPrefix *StoreThis = new_EqIpPrefix();
			StoreThis->ipaddress = start;
			StoreThis->prefixe = end;
			vector_set(TempEqIpPrefix, StoreThis);

			BitSet *Temp = BitSet_new(RuleCount);
			BitSet_set(RuleCount - RuleNo - 1, Temp);
			vector_set_index(CBM, Eq_Id, Temp);

			//for remanining entrys if any
			for (j = start + 1; j <= end; j++)
			{
				if (RFCTable[j] == 0)
					RFCTable[j] = Eq_Id;
				else {
					BitSet *bs1 = vector_slot(CBM, RFCTable[j]);
					BitSet *bs2 = vector_slot(CBM, Eq_Id);
					BitSet_or(bs1, bs2);
				}
			}
		}
		else
		{
			/*for more specific IP address entry in RFC table. Subset of IP@ should not be given same eq_id as that of
			its superset */
			EqIpPrefix *ep = vector_slot(TempEqIpPrefix, RFCTable[start] - 1);
			if ((ep->ipaddress != start) &&
				(ep->prefixe != end))
			{
				BitSet *bs = vector_slot(CBM, RFCTable[start]);
				BitSet *Temp = BitSet_new(RuleCount);
				BitSet_set(RuleCount - RuleNo - 1, Temp);
				BitSet_or(Temp, bs);
				RFCTable[start] = ++Eq_Id; //storing at updated eq_id
				vector_set_index(CBM, Eq_Id, Temp);
				EqIpPrefix *StoreThis = new_EqIpPrefix();
				StoreThis->ipaddress = start;
				StoreThis->prefixe = end;
				vector_set(TempEqIpPrefix, StoreThis);

				for (j = start + 1; j <= end; j++)
				{
					if (RFCTable[j] == 0)
						RFCTable[j] = Eq_Id;
					else {
						BitSet *bs1 = vector_slot(CBM, RFCTable[j]);
						BitSet *bs2 = vector_slot(CBM, Eq_Id);
						BitSet_or(bs1, bs2);
					}
				}
			}
			else
			{
				BitSet *bs1 = vector_slot(CBM, RFCTable[start]);
				BitSet_set(RuleCount - RuleNo - 1, bs1);
			}
		}
	}
	else
	{
		BitSet *bs1 = vector_slot(CBM, RFCTable[start]);
		BitSet_set(RuleCount - RuleNo - 1, bs1);
	}
	return Eq_Id;
}

static void CreatePhase0_CBMTable(vector CBMTable, int Eq_Id, vector CBMList)
{
	/*Updating all CBM bitmaps with wildcard entry bitmap... here it will always be first entry in CBM table.*/
	for (int i = 0; i < Eq_Id; i++)
	{
		BitSet *b = vector_slot(CBMTable, i);
		BitSet *bsi = vector_slot(CBMList, i);
		BitSet *bs0 = vector_slot(CBMList, 0);
		BitSet_or(bsi, bs0);
		BitSet_or(b, bsi);
	}
}

static void CreatePhase1_RFC_CBM_Table(Phase0 *RFCPhase0, Phase1 *RFCPhase1, int RuleCount)
{
	int Eq_Id, CBMno;
	struct hash * HashMap = hash_create(BS_EQ_MAP_key, BS_EQ_MAP_cmp);
	int RFCTable0size, x, y, z, q;

	for (CBMno = 0; CBMno < 2; CBMno++)
	{
		BitSet *Temp0;
		BitSet *Temp1;
		BitSet *Temp2;
		BitSet *Temp3;
		BitSet *Temp;
		RFCTable0size = (RFCPhase0->Eq_ID[C1[CBMno][0]])
			* (RFCPhase0->Eq_ID[C1[CBMno][1]])
			* (RFCPhase0->Eq_ID[C1[CBMno][2]])
			* (RFCPhase0->Eq_ID[C1[CBMno][3]]);

		x = (RFCPhase0->Eq_ID[C1[CBMno][1]])
			* (RFCPhase0->Eq_ID[C1[CBMno][2]])
			* (RFCPhase0->Eq_ID[C1[CBMno][3]]);

		y = (RFCPhase0->Eq_ID[C1[CBMno][2]])
			* (RFCPhase0->Eq_ID[C1[CBMno][3]]);

		z = RFCPhase0->Eq_ID[C1[CBMno][3]];

		q = 0;
		Eq_Id = 0;

		hash_clean(HashMap, BS_EQ_MAP_free);
		RFCPhase1->RFCTable[CBMno] = SCMalloc(RFCTable0size * sizeof(int));
		RFCPhase1->CBMTable[CBMno] = vector_init(0);
		Temp = BitSet_new(RuleCount);

		for (int i = 0; i < RFCPhase0->Eq_ID[C1[CBMno][0]]; i++)
		{
			for (int j = 0; j < RFCPhase0->Eq_ID[C1[CBMno][1]]; j++)
			{
				for (int k = 0; k < RFCPhase0->Eq_ID[C1[CBMno][2]]; k++)
				{

					for (int m = 0; m < RFCPhase0->Eq_ID[C1[CBMno][3]]; m++)
					{
						BS_EQ_MAP *be;
						BS_EQ_MAP nbe = {};
						Temp0 = vector_slot(RFCPhase0->CBMTable[C1[CBMno][0]], i);
						Temp1 = vector_slot(RFCPhase0->CBMTable[C1[CBMno][1]], j);
						Temp2 = vector_slot(RFCPhase0->CBMTable[C1[CBMno][2]], k);
						Temp3 = vector_slot(RFCPhase0->CBMTable[C1[CBMno][3]], m);

						BitSet_or(Temp, Temp0);
						BitSet_and(Temp, Temp1);
						BitSet_and(Temp, Temp2);
						BitSet_and(Temp, Temp3);

						q = i * x + y * j + k * z + m;

						nbe.bs = Temp;

						if ((be = hash_lookup(HashMap, &nbe)) == NULL)
						{
							vector_set_index(RFCPhase1->CBMTable[CBMno], Eq_Id, BitSet_copy(Temp));

							nbe.eq_id = Eq_Id;

							hash_get(HashMap, (void *)&nbe, BS_EQ_MAP_copy);
							RFCPhase1->RFCTable[CBMno][q] = Eq_Id;
							Eq_Id++;
						}
						else
						{
							RFCPhase1->RFCTable[CBMno][q] = be->eq_id;
						}
						BitSet_clear(Temp);
					}
				}
			}
		}
		RFCPhase1->Eq_ID[CBMno] = Eq_Id;
		BitSet_free(Temp);
		hash_clean(HashMap, BS_EQ_MAP_free);

	}
	hash_free(HashMap);
}

static void CreatePhase2_RFC_CBM_Table(Phase1 *RFCPhase1, Phase2 *RFCPhase2, int RuleCount)
{
	int RFCTable0size = (RFCPhase1->Eq_ID[0])*(RFCPhase1->Eq_ID[1]);
	int y = (RFCPhase1->Eq_ID[1]);
	int z = 0;

	BitSet *Temp0;
	BitSet *Temp1;
	BitSet *Temp = BitSet_new(RuleCount);

	RFCPhase2->RFCTable = SCMalloc(RFCTable0size * sizeof(int));
	memset(RFCPhase2->RFCTable, 0, (RFCTable0size * sizeof(int)));

	for (int i = 0; i < RFCPhase1->Eq_ID[0]; i++)
	{
		Temp0 = vector_slot(RFCPhase1->CBMTable[0], i);
		for (int j = 0; j < RFCPhase1->Eq_ID[1]; j++)
		{
			Temp1 = vector_slot(RFCPhase1->CBMTable[1], j);

			BitSet_or(Temp, Temp0);
			BitSet_and(Temp, Temp1);

			z = y * i + j;

			RFCPhase2->RFCTable[z] = RuleCount - BitSet_length(Temp);

			BitSet_clear(Temp);
		}
	}

	BitSet_free(Temp);

}

static void RFCMapping(Phase0 *RFC_Phase0, Phase1 *RFC_Phase1, Phase2 *RFC_Phase2,
	struct rfc_rule*rule_list, int rule_count)
{
	unsigned int IPaddress_SA, IPaddress_DA;
	int IPdec = 0, Input_Prefix;
	unsigned int  *IP_SA, *IP_DA;
	int RuleNo = 0;
	int Portstartid, Portendid;
	int ProtocolId, ProtocolPrefix;
	struct rfc_rule*rule = rule_list;

	vector TempEqIpPrefix[MAX_PHASE0_CHUNKS];

	vector TempCBM[MAX_PHASE0_CHUNKS];
	for (int i = 0; i < MAX_PHASE0_CHUNKS; i++) {
		TempEqIpPrefix[i] = vector_init(0);
		TempCBM[i] = vector_init(0);
		vector_set(TempCBM[i], BitSet_new(rule_count));
	}


	for (int n = 0; n < rule_count; n++, rule++) {
		if (rule->sip.family == AF_INET)
		{
			//Source IP@ 1st Chunk
			IPaddress_SA = ntohl(rule->sip.u.prefix4.s_addr);
			Input_Prefix = rule->sip.prefixlen > 16 ? 16 : rule->sip.prefixlen;
			IPdec = IPaddress_SA >> 16;
			RFC_Phase0->Eq_ID[SIP_H_IDX] = CreatePhase0_RFCTable(RFC_Phase0->Eq_ID[SIP_H_IDX],
				RFC_Phase0->RFCTable[SIP_H_IDX],
				IPdec, Input_Prefix,
				16, TempEqIpPrefix[SIP_H_IDX],
				rule_count, RuleNo, TempCBM[SIP_H_IDX]);

			//Source IP@ 2nd Chunk
			IPdec = (IPaddress_SA & 0xFFFF);
			Input_Prefix = rule->sip.prefixlen > 16 ? (rule->sip.prefixlen - 16) : 0;
			RFC_Phase0->Eq_ID[SIP_L_IDX] = CreatePhase0_RFCTable(RFC_Phase0->Eq_ID[SIP_L_IDX],
				RFC_Phase0->RFCTable[SIP_L_IDX],
				IPdec, Input_Prefix, 16, TempEqIpPrefix[SIP_L_IDX],
				rule_count, RuleNo, TempCBM[SIP_L_IDX]);
		}
		else if (rule->sip.family == AF_INET6)
		{
			;
		}
		else {
			//Source IP@ 1st Chunk
			IPdec = ntohl(*(unsigned int*)&rule->sip.u.val[0]) >> 16;
			Input_Prefix = ntohl(*(unsigned int *)&rule->sip.u.val[4]) >> 16;
			RFC_Phase0->Eq_ID[SIP_H_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[SIP_H_IDX],
				RFC_Phase0->RFCTable[SIP_H_IDX],
				IPdec, Input_Prefix,
				TempEqIpPrefix[SIP_H_IDX],
				rule_count, RuleNo, TempCBM[SIP_H_IDX]);

			//Source IP@ 2nd Chunk
			IPdec = ntohl(*(unsigned int*)&rule->sip.u.val[0]) & 0xFFFF;
			Input_Prefix = ntohl(*(unsigned int*)&rule->sip.u.val[4]) & 0xFFFF;
			RFC_Phase0->Eq_ID[SIP_L_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[SIP_L_IDX],
				RFC_Phase0->RFCTable[SIP_L_IDX],
				IPdec, Input_Prefix, TempEqIpPrefix[SIP_L_IDX],
				rule_count, RuleNo, TempCBM[SIP_L_IDX]);
		}

		if (rule->dip.family == AF_INET)
		{
			//Destination IP@ 1st Chunk

			IPaddress_DA = ntohl(rule->dip.u.prefix4.s_addr);
			Input_Prefix = rule->dip.prefixlen > 16 ? 16 : rule->dip.prefixlen;
			IPdec = IPaddress_DA >> 16;;
			RFC_Phase0->Eq_ID[DIP_H_IDX] = CreatePhase0_RFCTable(RFC_Phase0->Eq_ID[DIP_H_IDX],
				RFC_Phase0->RFCTable[DIP_H_IDX],
				IPdec, Input_Prefix, 16, TempEqIpPrefix[DIP_H_IDX],
				rule_count, RuleNo, TempCBM[DIP_H_IDX]);

			//Destination IP@ 2nd chunk
			IPdec = (IPaddress_DA & 0xFFFF);
			Input_Prefix = rule->dip.prefixlen > 16 ? (rule->dip.prefixlen - 16) : 0;
			RFC_Phase0->Eq_ID[DIP_L_IDX] = CreatePhase0_RFCTable(RFC_Phase0->Eq_ID[DIP_L_IDX],
				RFC_Phase0->RFCTable[DIP_L_IDX],
				IPdec, Input_Prefix, 16, TempEqIpPrefix[DIP_L_IDX],
				rule_count, RuleNo, TempCBM[DIP_L_IDX]);
		}
		else if (rule->sip.family == AF_INET6)
		{
			;
		}
		else {
			//Source IP@ 1st Chunk
			IPdec = ntohl(*(unsigned int *)&rule->dip.u.val[0]) >> 16;
			Input_Prefix = ntohl(*(unsigned int *)&rule->dip.u.val[4]) >> 16;
			RFC_Phase0->Eq_ID[SIP_H_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[DIP_H_IDX],
				RFC_Phase0->RFCTable[DIP_H_IDX],
				IPdec, Input_Prefix,
				TempEqIpPrefix[DIP_H_IDX],
				rule_count, RuleNo, TempCBM[DIP_H_IDX]);

			//Source IP@ 2nd Chunk
			IPdec = ntohl(*(unsigned int*)&rule->dip.u.val[0]) & 0xFFFF;
			Input_Prefix = ntohl(*(unsigned int*)&rule->dip.u.val[4]) & 0xFFFF;
			RFC_Phase0->Eq_ID[DIP_L_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[DIP_L_IDX],
				RFC_Phase0->RFCTable[DIP_L_IDX],
				IPdec, Input_Prefix, TempEqIpPrefix[DIP_L_IDX],
				rule_count, RuleNo, TempCBM[DIP_L_IDX]);
		}

		//L4 Source port
		Portstartid = rule->sport.start;
		Portendid = rule->sport.end;
		RFC_Phase0->Eq_ID[SPORT_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[SPORT_IDX],
			RFC_Phase0->RFCTable[SPORT_IDX],
			Portstartid, Portendid, TempEqIpPrefix[SPORT_IDX],
			rule_count, RuleNo, TempCBM[SPORT_IDX]);
		//L4 Destination port
		Portstartid = rule->dport.start;
		Portendid = rule->dport.end;
		RFC_Phase0->Eq_ID[DPORT_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[DPORT_IDX],
			RFC_Phase0->RFCTable[DPORT_IDX],
			Portstartid, Portendid, TempEqIpPrefix[DPORT_IDX],
			rule_count, RuleNo, TempCBM[DPORT_IDX]);


		//Protocol field
		ProtocolId = rule->protocol.start;
		ProtocolPrefix = rule->protocol.end;
		RFC_Phase0->Eq_ID[PROTO_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[PROTO_IDX],
			RFC_Phase0->RFCTable[PROTO_IDX],
			ProtocolId, ProtocolPrefix, TempEqIpPrefix[PROTO_IDX],
			rule_count, RuleNo, TempCBM[PROTO_IDX]);
		//ifindex
		ProtocolId = rule->ifindex.start;
		ProtocolPrefix = rule->ifindex.end;
		RFC_Phase0->Eq_ID[IFIDX_IDX] = CreateRFCTable_Range(RFC_Phase0->Eq_ID[IFIDX_IDX],
			RFC_Phase0->RFCTable[IFIDX_IDX],
			ProtocolId, ProtocolPrefix, TempEqIpPrefix[IFIDX_IDX],
			rule_count, RuleNo, TempCBM[IFIDX_IDX]);
		RuleNo++;

	}

	for (int j = 0; j < MAX_PHASE0_CHUNKS; j++)
	{
		RFC_Phase0->Eq_ID[j]++;
		vector_set(RFC_Phase0->CBMTable[j], BitSet_new(RFC_Phase0->Eq_ID[j]));

		for (int i = 0; i < RFC_Phase0->Eq_ID[j]; i++)
			vector_set_index(RFC_Phase0->CBMTable[j], i, BitSet_new(rule_count));
	}

	for (int j = 0; j < MAX_PHASE0_CHUNKS; j++)
	{
		CreatePhase0_CBMTable(RFC_Phase0->CBMTable[j], RFC_Phase0->Eq_ID[j], TempCBM[j]);
	}

	//RFC tables for Phase 1
	CreatePhase1_RFC_CBM_Table(RFC_Phase0, RFC_Phase1, rule_count);
	//RFC tables for phase 2
	CreatePhase2_RFC_CBM_Table(RFC_Phase1, RFC_Phase2, rule_count);

	/* free memory */
	/* free Phase1 CBM */
	for (int i = 0; i < MAX_PHASE1_CHUNKS; i++)
	{
		for (int j = 0; j < vector_active(RFC_Phase1->CBMTable[i]); j++)
		{
			BitSet_free(vector_slot(RFC_Phase1->CBMTable[i], j));
		}
		vector_free(RFC_Phase1->CBMTable[i]);
		RFC_Phase1->CBMTable[i] = NULL;
	}

	/* free Phase0 CBM */
	for (int i = 0; i < MAX_PHASE0_CHUNKS; i++)
	{
		for (int j = 0; j < vector_active(RFC_Phase0->CBMTable[i]); j++)
		{
			BitSet_free(vector_slot(RFC_Phase0->CBMTable[i], j));
		}
		RFC_Phase0->CBMTable[i] = NULL;
	}

	/* free temp EqIpPrefix and CBM */
	for (int i = 0; i < MAX_PHASE0_CHUNKS; i++)
	{
		for (int j = 0; j < vector_active(TempEqIpPrefix[i]); j++)
		{
			free_EqlpPrefix(vector_slot(TempEqIpPrefix[i], j));
		}
		vector_free(TempEqIpPrefix[i]);
		for (int j = 0; j < vector_active(TempCBM[i]); j++)
		{
			BitSet_free(vector_slot(TempCBM[i], j));
		}
		vector_free(TempCBM[i]);
	}
}

static void phase0_free(Phase0 *p)
{
	for (int j = 0; j < MAX_PHASE0_CHUNKS; j++)
	{
		if (p->RFCTable[j])
			SCFree(p->RFCTable[j]);
		p->RFCTable[j] = NULL;

		if (p->CBMTable[j])
		{
			for (int i = 0; i < vector_active(p->CBMTable[j]); i++)
			{
				BitSet_free(vector_slot(p->CBMTable[j], i));
			}
			vector_free(p->CBMTable[j]);
		}
		p->CBMTable[j] = NULL;
	}

	return;
}

static void phase1_free(Phase1 *p)
{
	for (int j = 0; j < MAX_PHASE1_CHUNKS; j++)
	{
		p->Eq_ID[j] = 0;
		if (p->RFCTable[j])
			SCFree(p->RFCTable[j]);
		p->RFCTable[j] = NULL;

		if (p->CBMTable[j])
		{
			for (int i = 0; i < vector_active(p->CBMTable[j]); i++)
			{
				BitSet_free(vector_slot(p->CBMTable[j], i));
			}
			vector_free(p->CBMTable[j]);
		}
		p->CBMTable[j] = NULL;
	}

	return;
}

static void phase2_free(Phase2 *p)
{
	if (p->RFCTable)
		SCFree(p->RFCTable);
	p->RFCTable = NULL;

	return;
}

void RFC_table_init(struct RFC_table *table)
{
	Phase0 *phase0 = &table->phase0;
	Phase1 *phase1 = &table->phase1;
	Phase2 *phase2 = &table->phase2;

	phase2_free(phase2);
	phase1_free(phase1);
	phase0_free(phase0);

	for (int j = 0; j < PROTO_IDX; j++)
	{
		phase0->RFCTable[j] = SCMalloc(MAX_CHUNK_SIZE * sizeof(unsigned short int));
		memset(phase0->RFCTable[j], 0, (MAX_CHUNK_SIZE * sizeof(unsigned short int)));
		phase0->CBMTable[j] = vector_init(0);
	}
	phase0->RFCTable[PROTO_IDX] = SCMalloc(256 * sizeof(unsigned short int));
	memset(phase0->RFCTable[PROTO_IDX], 0, (256 * sizeof(unsigned short int)));
	phase0->CBMTable[PROTO_IDX] = vector_init(0);

	phase0->RFCTable[IFIDX_IDX] = SCMalloc(256 * sizeof(unsigned short int));
	memset(phase0->RFCTable[IFIDX_IDX], 0, (256 * sizeof(unsigned short int)));
	phase0->CBMTable[IFIDX_IDX] = vector_init(0);


}

void RFC_table_free(int index)
{
	struct RFC_table *rfc_tb = &_rfc_table[index];
	phase0_free(&rfc_tb->phase0);
	phase1_free(&rfc_tb->phase1);
	phase2_free(&rfc_tb->phase2);
}

/* calculate all rule and get index table */
int rfc_commit(struct rfc_rule *rule_list, unsigned int rule_size) {
	struct RFC_table *cal_table = &_rfc_table[(_rfc_table_idx + 1) & 1];
	if (MAX_RULE_NUM < rule_size)
		return -1;

	RFC_table_init(cal_table);
	RFCMapping(&cal_table->phase0, &cal_table->phase1, &cal_table->phase2, rule_list, rule_size);

	_current_use_table = cal_table;
	_rfc_table_idx++;

	return 0;
}

/* match a packet flow and return rule id */
int rfc_match(const unsigned int sip, const unsigned int dip,
	const unsigned short int sport, const unsigned short int dport,
	const unsigned short int protocol, const unsigned short int ifindex)
{
	int phase0_idx[8];
	int phase1_idx[2];
	int idx10;
	struct RFC_table * cur_table = _current_use_table;
	Phase0 * phase0 = &cur_table->phase0;
	Phase1 * phase1 = &cur_table->phase1;
	Phase2 * phase2 = &cur_table->phase2;

	phase0_idx[SIP_H_IDX] = phase0->RFCTable[SIP_H_IDX][sip >> 16];
	phase0_idx[SIP_L_IDX] = cur_table->phase0.RFCTable[SIP_L_IDX][(sip&MAX_USHORT_MASK)];
	phase0_idx[DIP_H_IDX] = cur_table->phase0.RFCTable[DIP_H_IDX][dip >> 16];
	phase0_idx[DIP_L_IDX] = cur_table->phase0.RFCTable[DIP_L_IDX][(dip&MAX_USHORT_MASK)];
	phase0_idx[SPORT_IDX] = cur_table->phase0.RFCTable[SPORT_IDX][sport];
	phase0_idx[DPORT_IDX] = cur_table->phase0.RFCTable[DPORT_IDX][dport];
	phase0_idx[PROTO_IDX] = cur_table->phase0.RFCTable[PROTO_IDX][protocol];
	phase0_idx[IFIDX_IDX] = cur_table->phase0.RFCTable[IFIDX_IDX][ifindex];

#ifdef DEBUG
	for (int i = 0; i < MAX_IDX; i++)
		fprintf(stdout, "phase0_idx[%d]=%d\n", i,
			phase0_idx[i]);
#endif
	/* idx8 = chunks[8][Nb*Nc*Nd*idx0 +Nc*Nd*idx3 + Nd*idx4+idx6] :
		   idx9 = chunks[9][Nb*Nc*Nd*idx1 +Nc*Nd*idx2 + Nd*idx5+idx7]
		*/
	for (int i = 0; i < 2; i++) {
		phase1_idx[i] = phase1->RFCTable[i]
			[phase0_idx[C1[i][0]] * phase0->Eq_ID[C1[i][1]] * phase0->Eq_ID[C1[i][2]] * phase0->Eq_ID[C1[i][3]]
			+ phase0_idx[C1[i][1]] * phase0->Eq_ID[C1[i][2]] * phase0->Eq_ID[C1[i][3]]
			+ phase0_idx[C1[i][2]] * phase0->Eq_ID[C1[i][3]]
			+ phase0_idx[C1[i][3]]];
#ifdef DEBUG
		fprintf(stdout, "phase1_idx[%d]:%d \n", i, phase1_idx[i]);
#endif
	}


	/* idx10 = chunks[10][Nb*idx8 + idx9 ]*/
	idx10 = phase1_idx[0] * phase1->Eq_ID[1] + phase1_idx[1];
#ifdef DEBUG
	fprintf(stdout, "idx10:%d \n", idx10);
#endif

	/* rule_id = summary[idx10] */
	return phase2->RFCTable[idx10];
}

void dump_rfc_table(char *file)
{
	struct RFC_table * cur_table = _current_use_table;
	Phase0 * phase0 = &cur_table->phase0;
	Phase1 * phase1 = &cur_table->phase1;
	Phase2 * phase2 = &cur_table->phase2;
	FILE *fd;
	int count = 0;

	char fn[128] = {};
	snprintf(fn, 128, "%s%s", file, "phase0");
	fd = fopen(fn, "w");

	fprintf(fd, "Phase 0:\n\teqid:");
	for (int i = 0; i < MAX_PHASE0_CHUNKS; i++)
		fprintf(fd, " %d", phase0->Eq_ID[i]);
	fprintf(fd, "\n");

	fprintf(fd, "\t rfc table:\n\t");
	for (int i = 0; i < PROTO_IDX; i++) {
		count = 1;
		fprintf(fd, "chunk#%d\n\t", i);
		for (int j = 0; j < 65536; j++) {
			if (((count) % 32) == 0) fprintf(fd, "\n\t");
			if (phase0->RFCTable[i][j]) {
				fprintf(fd, "%d:%d ", j, phase0->RFCTable[i][j]);
				count++;
			}
		}
		fprintf(fd, "\n----------------------------------------------------------------\n\t");
	}
	for (int j = 0; j < 256; j++) {
		if ((j % 32) == 0) fprintf(fd, "\n\t");
		fprintf(fd, "%d ", phase0->RFCTable[PROTO_IDX][j]);
	}
	fprintf(fd, "\n----------------------------------------------------------------");
	for (int j = 0; j < 256; j++) {
		if ((j % 32) == 0) fprintf(fd, "\n\t");
		fprintf(fd, "%d ", phase0->RFCTable[IFIDX_IDX][j]);
	}
	fprintf(fd, "\n----------------------------------------------------------------");
	fclose(fd);

	snprintf(fn, 128, "%s%s", file, "phase1");
	fd = fopen(fn, "w");
	fprintf(fd, "\nPhase 1:\n\teqid:");
	for (int i = 0; i < MAX_PHASE1_CHUNKS; i++)
		fprintf(fd, " %d", phase1->Eq_ID[i]);
	fprintf(fd, "\n");

	fprintf(fd, "\t rfc table:");
	for (int i = 0; i < MAX_PHASE1_CHUNKS; i++) {
		int RFCTable0size = (phase0->Eq_ID[C1[i][0]])*(phase0->Eq_ID[C1[i][1]])*(phase0->Eq_ID[C1[i][2]])*(phase0->Eq_ID[C1[i][3]]);
		for (int j = 0; j < RFCTable0size; j++) {
			if ((j % 64) == 0) fprintf(fd, "\n\t");
			fprintf(fd, "%d ", phase1->RFCTable[i][j]);
		}
		fprintf(fd, "\n----------------------------------------------------------------");
	}

	fclose(fd);

	snprintf(fn, 128, "%s%s", file, "phase2");
	fd = fopen(fn, "w");
	int RFCTable0size = phase1->Eq_ID[0] * phase1->Eq_ID[1];
	fprintf(fd, "\nPhase 2:");
	for (int i = 0; i < RFCTable0size; i++)
	{
		if ((i % 64) == 0) fprintf(fd, "\n\t");
		fprintf(fd, "%d ", phase2->RFCTable[i]);
	}
	fclose(fd);
}

