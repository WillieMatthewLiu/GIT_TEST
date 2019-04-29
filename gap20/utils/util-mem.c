
#include "app_common.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <semaphore.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include "threads.h"
#ifdef USER_MEM_ALLOC
typedef uint64_t Size;
typedef int		Bool;

typedef uint8_t Data;                  /* data */
typedef uint16_t Status;               /* status */

#define SS_MAX_STSKS                 30

#define SsSemaId                        sem_t
#define ssInitSema(s, c)                sem_init(s, 0, c)
#define ssWaitSema(s)                   sem_wait(s)
#define ssPostSema(s)                   sem_post(s)
#define ssDestroySema(s)                sem_destroy(s)

#define SLockId                         SCSpinlock
#define SInitLock(l, t)                 SCSpinInit(l, t)
#define SLock(l)                        SCSpinLock(l)
#define SUnlock(l)                      SCSpinUnlock(l)
#define SDestroyLock(l) 				SCSpinDestroy((l))

#define SS_LOCK_THREAD_SHARE                   0

#define NULLP NULL
#define SS_MAX_LOCAL_REGS			1
#define SS_MAX_POOLS_PER_REG 8
#define MT_MAX_BKTS             8
#define  CMM_MAX_BKT_ENT    30  
#define MT_BKTQNSIZE	64
#define  CMM_MAX_MAP_ENT    256

#define ENABLE_ERR_CHECK 1

#define DOMAIN_MAX_NUM	32
#define DOMAIN_NAME_LEN	64

// must be FE_CACHELINE_SIZE alignment
#define MT_BKT_0_DSIZE          64
#define MT_BKT_1_DSIZE          128
#define MT_BKT_2_DSIZE          256      /* Fill in this value as required */
#define MT_BKT_3_DSIZE          512      /* Fill in this value as required */ 
#define MT_BKT_4_DSIZE          1024      /* Fill in this value as required */ 
#define MT_BKT_5_DSIZE          2048      /* Fill in this value as required */ 
#define MT_BKT_6_DSIZE          4096      /* Fill in this value as required */ 
#define MT_BKT_7_DSIZE          8192      /* Fill in this value as required */ 
#define BKT_0_NUMBLKS     32 * 1024
#define BKT_1_NUMBLKS     4 * 1024
#define BKT_2_NUMBLKS     128 * 1024
#define BKT_3_NUMBLKS     32 * 1024
#define BKT_4_NUMBLKS     4 * 1024
#define BKT_5_NUMBLKS     2 * 1024
#define BKT_6_NUMBLKS     1 * 1024
#define BKT_7_NUMBLKS     2 * 1024
#define SM_HEAP_SIZE            (64 * 0x100000)

#define MT_BKT_MAX_DSIZE	MT_BKT_7_DSIZE

#define BKT_MERGE_PERCENTAGE	20
#define BKT_FORCE_MERGE_PERCENTAGE	5
#define BKT_FREED_MERGE_PERCENTAGE	5

/* Bucket configuration structure. */
typedef struct cmMmBktCfg
{
	Size  blkSize;              /* Size of the memory block */
	uint32_t   numBlks;           /* Number of the block in the bucket */
}CmMmBktCfg;

typedef struct ssMemRegCfg
{
	char		*name;
	uint8_t        numBkts;     /* No.of bkts configured in this region */
	Size      heapSize;    /* heap size available in this region */
	CmMmBktCfg  bkt[SS_MAX_POOLS_PER_REG]; /* bkt configuration */
} SsMemRegCfg;

typedef Data     CmMmEntry;

/* Size-To-Bucket map table structure */
typedef struct cmMmMapBkt
{
	uint16_t   bktIdx;              /* The index to the memory bucket */

#if (ENABLE_ERR_CHECK)
	uint16_t   numReq;              /* Number of the allocation request */
	uint16_t   numFailure;          /* Number of allocation failure form the bucket */
#endif

}CmMmMapBkt;

/* Heap entry structure linked in the heap control block */
typedef struct cmHEntry
{
	struct cmHEntry  *next; 		 /* Pointer to the next entry block */
	Size	   size;			 /* size of the heap entry block */
}CmHEntry;

/* Memory bucket structure */
typedef struct cmMmBkt 			   /* Bucket Structure */
{
	CmMmEntry	*next;		   /* Pointer to the next memory block */
#ifdef TRI_BLK_TAIL
	CmMmEntry	*tail;		   /* Pointer to the tail memory block */
#endif
	CmMmEntry	*freeHead;		   /* Pointer to the head of to-be-freed memory block */
	CmMmEntry	*freeTail;		   /* Pointer to the tail of to-be-freed memory block */
	Size		 size;		   /* Size of the block */
	uint32_t		  numBlks;		/* Total number of blocks in the bucket */
	uint32_t		  numAlloc; 	/* Number of blocks allocated */
	uint32_t		  numToBeFreed; 	/* Number of blocks allocated */
	SLockId 	 bktLock;	   /* Lock to protect the bucket pool */
	uint32_t		  maxAlloc; 	/* Max number of blocks allocated, for statistics */

	Data	 *vStart;			/* Memory start address */
	Data	 *vEnd; 			/* Memory end address */
}CmMmBkt;

/* Heap control block */
typedef struct cmMmHeapCb
{
	uint32_t	regionId;
	Data	 *vStart;			/* Memory start address */
	Data	 *vEnd; 			/* Memory end address */
	CmHEntry *next; 			/* Next heap block entry */
	Size	  avlSize;			/* Total available memory */
	Size	  avlLeast;			/* Minimum size that can be allocated */
	Size	  minSize;			/* Minimum size that can be allocated */

	SLockId   heapLock; 		/* Lock to protect the heap pool */

	uint16_t	   numReq;			 /* Number of allocation request */
	uint16_t	   numFree;			 /* Number of free request */
#if (ENABLE_ERR_CHECK)
	uint16_t	   numFragBlk;		 /* Number of fragmented block */
	uint16_t	   numFailure;		 /* Number of allocation failure */
#endif

}CmMmHeapCb;

/* Memory region control block */
typedef struct cmMmRegCb
{
	int32_t		RegionId;
	char		name[DOMAIN_NAME_LEN];
	Bool		  used; 						  /* entry used? */
	pthread_t	pt;

	Data		  *start;						  /* start address */
	Size		  size; 						  /* size */

	Size		 bktSize;		/* Size of the memory used for the bucket pool */
	uint16_t		  bktQnPwr; 	 /* Quantum size of the bucket pool */
	Size		 bktMaxBlkSize; /* Maximum size of block in the bucket pool */
	uint16_t		  numBkts;		 /* Number of buckets in the Bucket Pool */

	CmMmMapBkt	 mapTbl[CMM_MAX_MAP_ENT]; /* size-to-bucket map table */
	CmMmBkt 	 bktTbl[CMM_MAX_BKT_ENT]; /* Pointer to the memory bkt tbl */

	Bool		 heapFlag;		/* Set to true if the heap pool is configured */
	Size		 heapSize;		/* Size of the heap pool */
	CmMmHeapCb	 heapCb;		/* Heap pool control block */
}CmMmRegCb;

typedef struct memBlockHead {
	int32_t	RegionId;
	uint32_t	size;
}MemBlockHeader;

#define RET_NOK (-1)
#define RET_OK (0)

#define PTR_SIZE_0	((void*)0xf0f0f0f0)

#define FE_CACHE_LINE_SIZE   64 // XLP_CACHELINE_SIZE
#define CACHELINE_SIZE 64

#define CMM_DATALIGN(s, msz)  (((Size)(s) % msz) ? ((Size)(s) + ((msz - (Size)(s) % msz))): (Size)(s)) 

#define XXX_ALIGNED_DATASIZE(s,xxx) ((Size)(s) % xxx ? \
    ((Size)(s) + (xxx - ((Size)(s) % xxx))) : (Size)(s))

#define CACHELINE_ALIGNED_DATASIZE(s) XXX_ALIGNED_DATASIZE(s,FE_CACHE_LINE_SIZE)
#define CACHELINE_ALIGNED_ADDR(addr) (((uintptr_t)(addr)) & ~(CACHELINE_SIZE-1))
#define CMM_MINBUFSIZE   (CACHELINE_ALIGNED_DATASIZE(sizeof(CmHEntry)))

static int32_t		DomainNum = 0;
static __thread int32_t DomainIndex = -1;
static CmMmRegCb ThreadMemoryRegion[DOMAIN_MAX_NUM];

static SsMemRegCfg ScMemoryCfg[] =
{
	{
		"Main",
		MT_MAX_BKTS,							/* number of buckets */
		SM_HEAP_SIZE,							/* heap size */
		{
			{MT_BKT_0_DSIZE, BKT_0_NUMBLKS},	/* block size, no. of blocks */
			{MT_BKT_1_DSIZE, BKT_1_NUMBLKS},	 /* block size, no. of blocks */
			{MT_BKT_2_DSIZE, BKT_2_NUMBLKS},	/* block size, no. of blocks */
			{MT_BKT_3_DSIZE, BKT_3_NUMBLKS},	 /* block size, no. of blocks */
			{MT_BKT_4_DSIZE, BKT_4_NUMBLKS},	 /* block size, no. of blocks */
			{MT_BKT_5_DSIZE, BKT_5_NUMBLKS},	 /* block size, no. of blocks */
			{MT_BKT_6_DSIZE, BKT_6_NUMBLKS},	 /* block size, no. of blocks */
			{MT_BKT_7_DSIZE, BKT_7_NUMBLKS},	 /* block size, no. of blocks */
		},
	},
	{
		"Detect",
		8,							/* number of buckets */
		(32 * 0x100000),							/* heap size */
		{
			{MT_BKT_0_DSIZE, 2 * 1024},
			{MT_BKT_1_DSIZE, 1024},
			{MT_BKT_2_DSIZE, 256},
			{MT_BKT_3_DSIZE, 256},
			{MT_BKT_4_DSIZE, 1024},
			{MT_BKT_5_DSIZE, 256},
			{MT_BKT_4_DSIZE, 256},
			{MT_BKT_5_DSIZE, 256},
		},
	},
	{
		"RxAFP",
		4,							/* number of buckets */
		(16 * 0x100000),							/* heap size */
		{
			{MT_BKT_0_DSIZE, 1024},
			{MT_BKT_1_DSIZE, 512},
			{MT_BKT_2_DSIZE, 256},
			{MT_BKT_3_DSIZE, 256},
		},
	},
	{
		"PcapFile",
		6,							/* number of buckets */
		(16 * 0x100000),							/* heap size */
		{
			{MT_BKT_0_DSIZE, 1024},
			{MT_BKT_1_DSIZE, 256},
			{MT_BKT_2_DSIZE, 32},
			{MT_BKT_3_DSIZE, 32},
			{MT_BKT_4_DSIZE, 32},
			{MT_BKT_5_DSIZE, 32},
		},
	},
	{
		"ReceivePcapFile",
		2,							/* number of buckets */
		(4 * 0x100000), 						/* heap size */
		{
			{MT_BKT_0_DSIZE, 1024},
			{MT_BKT_1_DSIZE, 1024},
		},
	},
	{
		"UnixManagerThread",
		2,							/* number of buckets */
		(4 * 0x100000), 						/* heap size */
		{
			{MT_BKT_0_DSIZE, 256},
			{MT_BKT_1_DSIZE, 32},
		},
	},
	{
		"FlowManagerThread",
		4,							/* number of buckets */
		(4 * 0x100000),						/* heap size */
		{
			{MT_BKT_0_DSIZE, 512},
			{MT_BKT_1_DSIZE, 32},
			{MT_BKT_2_DSIZE, 32},
			{MT_BKT_3_DSIZE, 32},
		},
	},
	{
		"SCPerf",
		1,							/* number of buckets */
		(1 * 0x100000), 					/* heap size */
		{
			{MT_BKT_0_DSIZE, 32},
		},
	},
	{
		"",							/* This is the default memory setting for un-configured thread */
		6,							/* number of buckets */
		(32 * 0x100000), 						/* heap size */
		{
			{MT_BKT_0_DSIZE, 1024},
			{MT_BKT_1_DSIZE, 256},
			{MT_BKT_2_DSIZE, 32},
			{MT_BKT_3_DSIZE, 32},
			{MT_BKT_4_DSIZE, 32},
			{MT_BKT_5_DSIZE, 32},
		},
	},
};
#define MEM_CONFIG_NUM	(sizeof(ScMemoryCfg) / sizeof(SsMemRegCfg))

static CmMmRegCb* ssiGetThreadMemoryRegion(void)
{
	if (DomainIndex >= 0 && DomainIndex < DomainNum)
	{
		return &ThreadMemoryRegion[DomainIndex];
	}
	else
	{
		pthread_t self = pthread_self();
		int32_t i, j;

		/* First time to use memory region. Find the domain index */
		for (j = 0; j < 5; j++)
		{
			for (i = 0; i < DomainNum; i++)
			{
				if (pthread_equal(self, ThreadMemoryRegion[i].pt))
					return &ThreadMemoryRegion[i];
			}
			/* The thread may run before memory region inited. Wait for some time */
			sleep(1);
		}
		/* Not found */
		printf("Memory Region for thread %ld not found!\n", self);
		return NULL;
	}
}

#if 0
/*
*
*       Fun:   cmMmRegDeInit
*
*       Desc:  Deinitialize the memory region. The function call SDeregRegion
*              to deregister the memory region with System Service.
*
*
*       Ret:   RET_OK     - successful
*              RFAILED - unsuccessful.
*
*       Notes: The memory owner calls this function to deinitialize the region.
*              The memory manager does not return the memory to the system.
*              Before calling this function, the memory owner must be sure that
*              no layer is using any memory block from this region. On
*              successful return from the function, any request to the memory
*              manager to allocate/deallocate memory will fail. The memory owner
*              can reuse the memory for other region or return the memory to the
*              system memory pool.
*
*
*
*       File:  cm_mem.c
*
*/
static int16_t cmMmRegDeInit
(
	CmMmRegCb   *regCb
)
{
#ifndef SS_SINGLE_THREADED   
	uint16_t  bktIdx;
#endif

#if (ENABLE_ERR_CHECK)

	/* error check on parameters */
	if (regCb == NULLP)
	{
		return(RET_NOK);
	}

#endif

	/* First to deregister the memory region with SSI */
	regCb->used = FALSE;
	regCb->start = NULLP;
	regCb->size = 0;

#ifndef SS_SINGLE_THREADED   
	if (regCb->bktSize)
	{
		/* Bucket pool is configured */

		/* Free the initialzed locks of the buckets */
		for (bktIdx = regCb->numBkts; bktIdx > 0;)
		{
			SDestroyLock(&(regCb->bktTbl[--bktIdx].bktLock));
		}
	}

	if (regCb->heapFlag)
	{
		/* Heap pool is configured */

		/* Destroy the bucket lock */
		SDestroyLock(&regCb->heapCb.heapLock);
	}
#endif

	return(RET_OK);

} /* end of cmMmRegDeInit */
#endif

int16_t SRegInfoShow(char* show_buf, int32_t max_len, int32_t region_id)
{
	CmMmRegCb *regionCb;
	int32_t cur_buf_len = 0;
	int32_t idx, i;
	int32_t max_buf_len = max_len;
	Size totalSize = 0, bucketUsed, totalBucketUsed = 0, totalHeapSize = 0, totalHeapUsedSize = 0;

	if (region_id < 0 || region_id > DomainNum)
	{
		cur_buf_len = snprintf(show_buf, max_buf_len,
			"Invalid Thread Memory Region ID: %d!\t\r\n", region_id);
		max_buf_len -= cur_buf_len;
		show_buf += cur_buf_len;
		region_id = 0;
	}
	else if (region_id != 0)
	{
		regionCb = &ThreadMemoryRegion[region_id - 1];
		if (!regionCb->used)
		{
			cur_buf_len = snprintf(show_buf, max_buf_len,
				"Unused Thread Memory Region ID: %d!\t\r\n", region_id);
			max_buf_len -= cur_buf_len;
			show_buf += cur_buf_len;
			region_id = 0;
		}
	}

	if (region_id == 0)
	{
		cur_buf_len = snprintf(show_buf, max_buf_len,
			"\r\nThread Memory Regions:\r\n"
			"============================================================================================\r\n"
			"Index           Name         Size  MaxUsed  BucketSize  BucketMaxUsed  HeapSize  HeapMaxUsed\r\n"
			"============================================================================================\r\n"
		);
		max_buf_len -= cur_buf_len;
		show_buf += cur_buf_len;
		regionCb = &ThreadMemoryRegion[0];
		for (i = 0; i < DomainNum; i++, regionCb++)
		{
			if (regionCb == NULLP || !regionCb->used)
				continue;
			bucketUsed = 0;
			for (idx = 0; idx < regionCb->numBkts; idx++)
			{
				bucketUsed += regionCb->bktTbl[idx].size * regionCb->bktTbl[idx].maxAlloc;
			}
			cur_buf_len = snprintf(show_buf, max_buf_len,
				"%2d  %20s    %4ldM    %3ld%%   %4ldM        %3ld%%        %4ldM        %3ld%%\r\n"
				, regionCb->RegionId + 1
				, regionCb->name
				, regionCb->size >> 20
				, (bucketUsed + regionCb->heapSize - regionCb->heapCb.avlLeast) * 100 / regionCb->size
				, (regionCb->size - regionCb->heapSize) >> 20
				, bucketUsed * 100 / (regionCb->size - regionCb->heapSize)
				, regionCb->heapSize >> 20
				, regionCb->heapSize ? (regionCb->heapSize - regionCb->heapCb.avlLeast) * 100 / regionCb->heapSize : 0
			);
			max_buf_len -= cur_buf_len;
			show_buf += cur_buf_len;

			totalSize += regionCb->size;
			totalBucketUsed += bucketUsed;
			totalHeapSize += regionCb->heapSize;
			totalHeapUsedSize += (regionCb->heapSize - regionCb->heapCb.avlLeast);
		}
		cur_buf_len = snprintf(show_buf, max_buf_len,
			"============================================================================================\r\n"
			"Total:                      %4ldM     %3ld%%  %4ldM        %3ld%%        %4ldM        %3ld%%\r\n"
			, totalSize >> 20
			, (totalBucketUsed + totalHeapUsedSize) * 100 / totalSize
			, (totalSize - totalHeapSize) >> 20
			, totalBucketUsed * 100 / (totalSize - totalHeapSize)
			, totalHeapSize >> 20
			, totalHeapSize ? totalHeapUsedSize * 100 / totalHeapSize : 0
		);
		max_buf_len -= cur_buf_len;
		show_buf += cur_buf_len;
		return (max_len - max_buf_len);
	}

	regionCb = &ThreadMemoryRegion[region_id - 1];
	cur_buf_len = snprintf(show_buf, max_buf_len,
		"\r\nThread %s Memory Region %d info:\r\n"
		"region size	   : %ld (%ldM)\r\n"
		"region start Addr:%#lx\r\n"
		"Heap size 	   : %ld (%ldM)\r\n"
		"Heap start Addr  : %#lx\r\n"
		"Heap end Addr    : %#lx\r\n"
		"Heap minSize	   : %ld (%ldM)\r\n"
		"Heap Allocated   : %lu (%ldM)\r\n"
		"Heap max used	   : %ld (%ldM, %ld%%)\r\n"
		"Heap req num	   : %d\r\n"
		"Heap free num    : %d\r\n"
#if (ENABLE_ERR_CHECK)
		"Heap frag num	: %d\r\n"
		"Heap fail num	: %d\r\n"
#endif
		, regionCb->name, regionCb->RegionId + 1
		, regionCb->size, regionCb->size >> 20
		, (uintptr_t)regionCb->start
		, regionCb->heapSize, regionCb->heapSize >> 20
		, (uintptr_t)regionCb->heapCb.vStart
		, (uintptr_t)regionCb->heapCb.vEnd
		, regionCb->heapCb.minSize, regionCb->heapCb.minSize >> 20
		, (regionCb->heapSize - regionCb->heapCb.avlSize), (regionCb->heapSize - regionCb->heapCb.avlSize) >> 20
		, (regionCb->heapSize - regionCb->heapCb.avlLeast), (regionCb->heapSize - regionCb->heapCb.avlLeast) >> 20, regionCb->heapSize ? (regionCb->heapSize - regionCb->heapCb.avlLeast) * 100 / regionCb->heapSize : 0
		, regionCb->heapCb.numReq
		, regionCb->heapCb.numFree
#if (ENABLE_ERR_CHECK)
		, regionCb->heapCb.numFragBlk
		, regionCb->heapCb.numFailure
#endif
	);
	max_buf_len -= cur_buf_len;
	show_buf += cur_buf_len;

	cur_buf_len = snprintf(show_buf, max_buf_len,
		"\r\nBucket Memory:\r\n"
		"==================================================================\r\n"
		"Bucket    Size      Number    Allocated   To-Be-Freed   Max Allocated    Max Usage\r\n"
		"==================================================================\r\n"
	);
	max_buf_len -= cur_buf_len;
	show_buf += cur_buf_len;

	for (idx = 0; idx < regionCb->numBkts; idx++)
	{
		cur_buf_len = snprintf(show_buf, max_buf_len,
			"%2d     %5lu     %8u    %8u     %8u     %8u          %2u%%\r\n",
			idx,
			regionCb->bktTbl[idx].size,
			regionCb->bktTbl[idx].numBlks,
			regionCb->bktTbl[idx].numAlloc,
			regionCb->bktTbl[idx].numToBeFreed,
			regionCb->bktTbl[idx].maxAlloc,
			regionCb->bktTbl[idx].numBlks ? regionCb->bktTbl[idx].maxAlloc * 100 / regionCb->bktTbl[idx].numBlks : 0
		);
		max_buf_len -= cur_buf_len;
		show_buf += cur_buf_len;
	}
	cur_buf_len = snprintf(show_buf, max_buf_len,
		"\r\n\r\n");
	max_buf_len -= cur_buf_len;
	show_buf += cur_buf_len;

	return (max_len - max_buf_len);
}/* end of SRegInfoShow */


/*
*
*       Fun:   cmMmHeapInit
*
*       Desc:  Initialize the heap pool.
*
*
*       Ret:   RET_OK     - successful
*              RFAILED - unsuccessful.
*
*       Notes: This function is called by the cmMmRegInit.
*
*       File:  cm_mem.c
*
*/
static void  cmMmHeapInit
(
	uint32_t	regionId,
	Data        *memAddr,
	CmMmHeapCb  *heapCb,
	Size         size
)
{

	/* Initialize the heap control block */
	heapCb->regionId = regionId;
	heapCb->vStart = memAddr;
	heapCb->vEnd = memAddr + size;
	heapCb->avlSize = size;
	heapCb->avlLeast = size;
	heapCb->minSize = CMM_MINBUFSIZE;

	heapCb->next = (CmHEntry *)memAddr;
	heapCb->next->next = NULLP;
	heapCb->next->size = size;

#if (ENABLE_ERR_CHECK)
	heapCb->numFragBlk = 0;
	heapCb->numReq = 0;
	heapCb->numFree = 0;
	heapCb->numFailure = 0;
#endif

} /* end of cmMmHeapInit */

/*
*
*       Fun:   cmHeapAlloc
*
*       Desc:  Allocates the memory block from the heap pool.
*
*
*       Ret:   RET_OK     - successful
*              RFAILED - unsuccessful.
*
*       Notes: This function is called by the cmAlloc. cmAlloc calls this
*              function when there is no memory block available in the bucket
*              and the  heap pool is configured.
*
*
*
*       File:  cm_mem.c
*
*/
static int16_t  cmHeapAlloc
(
	CmMmHeapCb  *heapCb,
	Data       **ptr,
	Size        *size
)
{
	CmHEntry  *prvHBlk;    /* Previous heap block */
	CmHEntry  *curHBlk;    /* Current heap block */
	Size       tmpSize;
	MemBlockHeader *memHeader;

	/* Roundup the requested size */
	*size = CMM_DATALIGN((*size), (heapCb->minSize));

	/* Check if the available total size is adequate. */
	if ((*size) >= heapCb->avlSize)
	{
#if (ENABLE_ERR_CHECK)
		/* Acquire the heap lock */
		SLock(&(heapCb->heapLock));
		heapCb->numFailure++;
		SUnlock(&(heapCb->heapLock));
#endif
		SCLogError(SC_ERR_MEM_ALLOC, "cmHeapAlloc failed: size too big: %lu bytes for heap", *size);
		return(RET_NOK);
	}

	/* Acquire the heap lock */
	SLock(&(heapCb->heapLock));

	heapCb->numReq++;

	/*
	 * Search through the heap block list in the heap pool of size
	 * greater than or equal to the requested size.
	 *
	 */
	prvHBlk = (CmHEntry *)&(heapCb->next);
	for (curHBlk = prvHBlk->next; curHBlk; curHBlk = curHBlk->next,
		prvHBlk = prvHBlk->next)
	{
		/*
		 * Since the size of the block is always multiple of CMM_MINBUFSIZE
		 * and the requested size is rounded to the size multiple of
		 * CMM_MINBUFSIZE, the difference between the size of the heap block
		 * and the size to allocate will be either zero or multiple of
		 * CMM_MINBUFSIZE.
		 */
		if ((*size) <= curHBlk->size)
		{
			if ((tmpSize = (curHBlk->size - (*size))))
			{
				/* Heap block of bigger size */
				*ptr = (Data *)curHBlk + tmpSize;
				curHBlk->size = tmpSize;
			}
			else
			{
				/* Heap block is same size of the requested size */
				*ptr = (Data *)curHBlk;
				prvHBlk->next = curHBlk->next;
			}
			heapCb->avlSize -= (*size);
			if (heapCb->avlLeast > heapCb->avlSize)
				heapCb->avlLeast = heapCb->avlSize;
#if (ENABLE_ERR_CHECK)
			heapCb->numFragBlk++;
#endif
			/* Release the lock */
			SUnlock(&(heapCb->heapLock));
			*size -= sizeof(MemBlockHeader);
			memHeader = (MemBlockHeader*)(*ptr);
			memHeader->RegionId = heapCb->regionId;
			memHeader->size = (uint32_t)(*size);
			*ptr += sizeof(MemBlockHeader);
			return(RET_OK);
		}
	}

#if (ENABLE_ERR_CHECK)
	heapCb->numFailure++;
#endif
	/* Release the lock */
	SUnlock(&(heapCb->heapLock));
	return(RET_NOK);
} /* end of cmHeapAlloc */


/*
*
*       Fun:   cmHeapFree
*
*       Desc:  Return the memory block from the heap pool.
*
*
*       Ret:   RET_OK     - successful
*              RFAILED - unsuccessful.
*
*       Notes: This function returns the memory block to the heap  pool. This
*              function is called by cmFree. The function does not check the
*              validity of the memory block. The caller must be sure that the
*              block was previously allocated and belongs to the heap pool. The
*              function maintain the sorting order of the memory block on the
*              starting address of the block. This function also do compaction
*              if the neighbouring blocks are already in the heap.
*
*
*
*       File:  cm_mem.c
*
*/
static int16_t  cmHeapFree
(
	CmMmHeapCb  *heapCb,
	Data        *ptr,
	Size        *size
)
{
	CmHEntry  *p;
	CmHEntry  *curHBlk;    /* Current heap block */
	MemBlockHeader *memHeader;

	/* Roundup the requested size */
	if (*size == 0)
	{
		ptr -= sizeof(MemBlockHeader);
		memHeader = (MemBlockHeader*)(ptr);
		*size = memHeader->size + sizeof(MemBlockHeader);
	}
	*size = CMM_DATALIGN(*size, (heapCb->minSize));

	/* increase the avlSize */
	heapCb->avlSize += *size;

	p = (CmHEntry *)ptr;

	/* Acquire the heap lock */
	SLock(&(heapCb->heapLock));
	for (curHBlk = heapCb->next; curHBlk; curHBlk = curHBlk->next)
	{
		/*
		 * The block will be inserted to maintain the sorted order on the
		 * starting address of the block.
		 */
		if (p > curHBlk)
		{
			if (!(curHBlk->next) ||
				(p < (curHBlk->next)))
			{
				/* Heap block should be inserted here */

				/*
				 * Check if the block to be returned can be merged with the
				 * current block.
				 */
				if (((Data *)curHBlk + curHBlk->size) == (Data *)p)
				{
					/* Merge the block */
					*size = (curHBlk->size += *size);
#if (ENABLE_ERR_CHECK)
					heapCb->numFragBlk--;
#endif
					p = curHBlk;
				}
				else
				{
					/* insert the block */
					p->next = curHBlk->next;
					p->size = *size;
					curHBlk->next = p;
				}

				/* Try to merge with the next block in the chain */
				if (((Data *)p + *size) == (Data *)(p->next))
				{
					/* p->next can not be NULL */
#if (ENABLE_ERR_CHECK)
					heapCb->numFragBlk--;
#endif
					p->size += p->next->size;
					p->next = p->next->next;
				}

				/* Release the lock */
				SUnlock(&(heapCb->heapLock));
				heapCb->numFree++;
				return(RET_OK);
			}
		}
		else if (p < curHBlk)
		{
			/*
			* Check if the block to be returned can be merged with the
			* current block.
			*/
			if (((Data *)p + *size) == (Data *)curHBlk)
			{
				/* Merge the block */
#if (ENABLE_ERR_CHECK)
				heapCb->numFragBlk--;
#endif
				p->size = *size + curHBlk->size;
				p->next = curHBlk->next;
			}
			else
			{
				/* insert the block */
				p->next = curHBlk;
				p->size = *size;
			}

			heapCb->next = p;

			/* Release the lock */
			SUnlock(&(heapCb->heapLock));
			heapCb->numFree++;
			return(RET_OK);
		}

	}

	if (heapCb->next == NULLP)
	{
		/* Heap block is empty. Insert the block in the head. */
		heapCb->next = p;
		p->next = NULLP;
		p->size = *size;

		/* Release the heap lock */
		SUnlock(&(heapCb->heapLock));
		heapCb->numFree++;
		return(RET_OK);
	}

	/* Release the lock */
	SUnlock(&(heapCb->heapLock));
	printf("cmHeapFree failed: addr %lX\n", (uint64_t)ptr);
	return(RET_NOK);
} /* end of cmHeapFree */

static int16_t  cmFreeBucket
(
	CmMmRegCb   *regCb,
	Data   *ptr,
	Size   *size
)
{
	uint16_t        bktIdx;
	CmMmBkt   *bkt;
	int i = 0, j = 0;
	MemBlockHeader *memHeader;
	CmMmRegCb* regCurCb;
	int threadCrossFree = TRUE;

#if (ENABLE_ERR_CHECK)

	/* error check on parameters */
	if ((regCb == NULLP) || (ptr == NULLP))
	{
		return(RET_NOK);
	}

	/* Check if the memory block is from the memory region */
	if (ptr >= ((CmMmRegCb *)regCb)->start +
		((CmMmRegCb *)regCb)->size)
	{
		printf("SCFree failed: address not found in memory region");
		return(RET_NOK);
	}

#endif

	ptr -= sizeof(MemBlockHeader);
	memHeader = (MemBlockHeader*)(ptr);
	*size = memHeader->size + sizeof(MemBlockHeader);
	if (NULL != (regCurCb = ssiGetThreadMemoryRegion()))
	{
		if (regCurCb->RegionId == regCb->RegionId)
			threadCrossFree = FALSE;
	}

	/*
	 * Check if the memory block was allocated from the bucket pool.
	 */

	if (ptr < (regCb->start + regCb->bktSize))
	{
		/* The memory block was allocated from the bucket pool */
		i = 0;
		j = regCb->numBkts - 1;
		while (i <= j)
		{
			bktIdx = (i + j) / 2;
#ifdef __MEM_DEBUG__          
			printf("bucket[%d]: vStart(%lx) -- vEnd(%lx) !\r\n",
				bktIdx, (uintptr_t)regCb->bktTbl[bktIdx].vStart,
				(uintptr_t)regCb->bktTbl[bktIdx].vEnd);
#endif
			if ((ptr >= regCb->bktTbl[bktIdx].vStart) &&
				(ptr <= regCb->bktTbl[bktIdx].vEnd))
			{
				break;
			}


			/* high part */
			if (ptr > regCb->bktTbl[bktIdx].vEnd)
			{
				i = bktIdx + 1;
				continue;
			}

			/*low part */
			if (ptr < regCb->bktTbl[bktIdx].vStart)
			{
				j = bktIdx - 1;
				continue;
			}

		}

		if (i > j)
		{
			/* Can't find valid bucket table. */
			printf("SCFree failed: Can't find valid bucket table, trying to search in heap()\n");
			return(RET_NOK);
		}

		/* Enqueue the memory block and return it to the user */
		bkt = &(regCb->bktTbl[bktIdx]);
		*size = bkt->size;

		/* Acquire the bucket lock */
		if (threadCrossFree)
		{
			SLock(&(bkt->bktLock));
		}

#ifdef __MEM_DEBUG__          
		printf("cmFree: Ptr(%lx), bkt(%d), bktsize(%d)\r\n",
			ptr, bktIdx, bkt->size);
#endif

		*((CmMmEntry **)ptr) = bkt->freeHead;
		bkt->freeHead = (CmMmEntry *)ptr;
		if (!bkt->freeTail)
			bkt->freeTail = (CmMmEntry *)ptr;

		/*
		* Decrement the statistics variable of number of memory block
		* allocated
		*/
		bkt->numAlloc--;
		bkt->numToBeFreed++;

		/* Release the lock */
		if (threadCrossFree)
		{
			SUnlock(&(bkt->bktLock));
		}
		return(RET_OK);
	}
	/* The memory block was allocated from the heap pool */
	/* We can't free a heap block without size */
	return(RET_NOK);

}


/*
*
*       Fun:   cmAlloc
*
*       Desc:  Allocate a memory block for the memory region.
*
*
*       Ret:   RET_OK     - successful
*              RFAILED - unsuccessful.
*
*       Notes:
*              The function allocates a memory block of size atleast equal to
*              the requested size. The size parameter will be updated with the
*              actual size of the memory block allocated for the request. The
*              CMM tries to allocate the memory block form the bucket pool. If
*              there is no memory in the bucket the CMM allocates the memory
*              block form the heap pool. This function is always called by the
*              System Service module.
*
*              The caller of the function should try to use the out value of
*              the size while returning the memory block to the region. However
*              the current design of the memory manager does not enforce to pass
*              the actual size of the memory block.  (Due to the SGetSBuf
*              semantics the layer will not able to pass the correct size of the
*              memory block while calling SPutSBuf).
*
*
*       File:  cm_mem.c
*
*/

static int16_t  cmAlloc
(
	CmMmRegCb   *regCb,
	Size   *size,
	Data  **ptr
)
{
	uint16_t        idx;
	CmMmBkt   *bkt;
	MemBlockHeader *memHeader;
	uint32_t bktAvalPercent;

#if (ENABLE_ERR_CHECK)

	/* error check on parameters */
	if ((regCb == NULLP) || (size == NULLP) || !(*size) || (ptr == NULLP))
	{
		return(RET_NOK);
	}
#endif
	*size += sizeof(MemBlockHeader);

	/*
	 * Check if the requested size is less than or equal to the maximum block
	 * size in the bucket.
	 */
	if (*size <= regCb->bktMaxBlkSize)
	{
		/* Get the map to the mapping table */
		idx = ((*size - 1) >> regCb->bktQnPwr);

#if (ENABLE_ERR_CHECK)
		if (regCb->mapTbl[idx].bktIdx == 0xFF)
		{
			/* Some fatal error in the map table initialization. */
			SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: map table initialization detected");
			return(RET_NOK);
		}
#endif

		/* Dequeue the memory block and return it to the user */
		bkt = &(regCb->bktTbl[regCb->mapTbl[idx].bktIdx]);

		/* While loop is introduced to use the "break statement inside */
		while (1)
		{
			/*
			 * Check if the size request is not greater than the size available
			 * in the bucket
			 */
			if (*size > bkt->size)
			{
				SCLogError(SC_ERR_MEM_ALLOC, "Requesting size %lu is bigger than current size %lu, trying the next one", *size, bkt->size);
				/* Try to go to the next bucket if available */
				if ((idx < (CMM_MAX_MAP_ENT - 1)) &&
					(regCb->mapTbl[++idx].bktIdx != 0xFF))
				{
					bkt = &(regCb->bktTbl[regCb->mapTbl[idx].bktIdx]);
				}
				else
				{
					/* This is the last bucket, try to allocate from heap */
					break;
				}
			}

			bktAvalPercent = (bkt->numBlks - bkt->numAlloc) * 100 / bkt->numBlks;
			if (bktAvalPercent < BKT_MERGE_PERCENTAGE && bkt->numToBeFreed > 0)
			{
				Bool doFree = FALSE;

				/* Check merge conditions again. Merge when:
				 * 1, There is too low percentage of available buckets
				 * 2, There is enough to-be-freed buckets
				 */
				if (BKT_FORCE_MERGE_PERCENTAGE > bktAvalPercent)
					doFree = TRUE;
				if (BKT_FREED_MERGE_PERCENTAGE < bkt->numToBeFreed * 100 / bkt->numBlks)
					doFree = TRUE;
				if (doFree)
				{
					printf("Thread %s bucket (%ld): merging free que! allocated %d, to-be-freed %d\n", regCb->name, bkt->size, bkt->numAlloc, bkt->numToBeFreed);
					/* Too few buckets left, try to merge to-be-freed queues */
					SLock(&(bkt->bktLock));

#ifdef TRI_BLK_TAIL
					*((CmMmEntry **)bkt->tail) = (CmMmEntry *)(bkt->freeHead);
					bkt->tail = (CmMmEntry *)(bkt->freeTail);
#else
					*((CmMmEntry **)(bkt->freeTail)) = bkt->next;
					bkt->next = (CmMmEntry *)(bkt->freeHead);
#endif
					bkt->numAlloc += bkt->numToBeFreed;
					bkt->numToBeFreed = 0;
					bkt->freeHead = NULLP;
					bkt->freeTail = NULLP;

					SUnlock(&(bkt->bktLock));
				}
			}

			/* Acquire the bucket lock */
			SLock(&(bkt->bktLock));

#if (ENABLE_ERR_CHECK)
			regCb->mapTbl[idx].numReq++;
#endif /* (ERRCLASS & ERRCLS_DEBUG) */

			if ((*ptr = bkt->next))
			{
				bkt->next = *((CmMmEntry **)(bkt->next));

				/*
				 * Increment the statistics variable of number of memory block
				 * allocated
				 */
				bkt->numAlloc++;
				(bkt->maxAlloc < bkt->numAlloc) ? bkt->maxAlloc = bkt->numAlloc :
					bkt->maxAlloc;

				/* Release the lock */
				SUnlock(&(bkt->bktLock));

				/* Update the size parameter */
				memHeader = (MemBlockHeader*)(*ptr);
				memHeader->RegionId = regCb->RegionId;
				*size = bkt->size - sizeof(MemBlockHeader);
				memHeader->size = (uint32_t)(*size);
				*ptr += sizeof(MemBlockHeader);
				return(RET_OK);
			}

#if (ENABLE_ERR_CHECK)
			regCb->mapTbl[idx].numFailure++;
#endif /* (ERRCLASS & ERRCLS_DEBUG) */

			/* Release the lock */
			SUnlock(&(bkt->bktLock));
			break;
		}
	}

	/* Memory not available in the bucket pool */
	if (regCb->heapFlag && (*size < regCb->heapSize))
	{
		/*
		 * The heap memory block is available. Allocate the memory block from
		 * heap pool.
		 */
		return(cmHeapAlloc(&(regCb->heapCb), ptr, size));
	}
	else
	{
		SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc (Thread %s) failed: size too big: %lu bytes", regCb->name, *size);
	}

	/* No memory available */
	*size -= sizeof(MemBlockHeader);
	return(RET_NOK);

} /* end of cmAlloc */

/*
*
*       Fun:   cmFree
*
*       Desc:  Return the memory block for the memory region.
*
*
*       Ret:   RET_OK     - successful
*              RFAILED - unsuccessful.
*
*       Notes: The user calls this function to return the previously allocated
*              memory block to the memory region. The memory manager does not
*              check the validity of the state of the memory block(like whether
*              it was allocated earlier). The caller must be sure that, the
*              address specified in the parameter 'ptr' is valid and was
*              allocated previously from same region.
*
*
*       File:  cm_mem.c
*
*/

static int16_t  cmFree
(
	CmMmRegCb   *regCb,
	Data   *ptr,
	Size*    size
)
{
#if (ENABLE_ERR_CHECK)
	/* error check on parameters */
	if ((regCb == NULLP) || (ptr == NULLP))
	{
		return(RET_NOK);
	}
#endif

	/* Check if the memory block is from the memory region */
	if (ptr < regCb->start
		|| ptr >= regCb->start + regCb->size)
	{
		/* Out of our memory region, just use system free() */
		free(ptr);
		return(RET_NOK);
	}
	else
	{
		if (ptr >= ((CmMmRegCb *)regCb)->heapCb.vStart)
		{
			return cmHeapFree(&(regCb->heapCb), ptr, size);
		}
		else
		{
			return cmFreeBucket(regCb, ptr, size);
		}
	}
} /* end of cmFree */

/*
*
*       Fun:   cmMmBktInit
*
*       Desc:  Initialize the bucket and the map table.
*
*
*       Ret:   RET_OK     - successful,
*              RFAILED - unsuccessful.
*
*       Notes: This function is called by the cmMmRegInit.
*
*       File:  cm_mem.c
*
*/
static void cmMmBktInit
(
	Data      **memAddr,
	CmMmRegCb  *regCb,
	SsMemRegCfg *cfg,
	uint16_t         bktIdx,
	uint16_t        *lstMapIdx
)
{
	uint32_t   cnt;
	uint16_t   idx;
	uint32_t   numBlks;
	Size  size;
	Data **next;

	size = cfg->bkt[bktIdx].blkSize;
	numBlks = cfg->bkt[bktIdx].numBlks;

	regCb->bktTbl[bktIdx].vStart = *memAddr;
	regCb->bktTbl[bktIdx].vEnd = *memAddr + size * (numBlks - 1);

	memset(*memAddr, 0, (size * numBlks));

	/* Reset the next pointer */
	regCb->bktTbl[bktIdx].next = NULLP;
	regCb->bktTbl[bktIdx].freeHead = NULLP;
	regCb->bktTbl[bktIdx].freeTail = NULLP;

	/* Initialize the link list of the memory block */
	next = &(regCb->bktTbl[bktIdx].next);
	for (cnt = 0; cnt < numBlks; cnt++)
	{
		*next = *memAddr;
		next = (CmMmEntry **)(*memAddr);
		*memAddr = (*memAddr) + size;
	}
	*next = NULLP;

#ifdef TRI_BLK_TAIL
	regCb->bktTbl[bktIdx].tail = (CmMmEntry *)next;
#endif

	/* Initialize the Map entry */
	idx = size / MT_BKTQNSIZE;

	/*
	 * Check if the size is multiple of quantum size. If not we need to initialize
	 * one more map table entry.
	 */
	if (size % MT_BKTQNSIZE)
	{
		idx++;
	}

	while (*lstMapIdx < idx)
	{
		regCb->mapTbl[*lstMapIdx].bktIdx = bktIdx;

#if (ENABLE_ERR_CHECK)
		regCb->mapTbl[*lstMapIdx].numReq = 0;
		regCb->mapTbl[*lstMapIdx].numFailure = 0;
#endif

		(*lstMapIdx)++;
	}

	/* Initialize the bucket structure */
	regCb->bktTbl[bktIdx].size = size;
	regCb->bktTbl[bktIdx].numBlks = numBlks;
	regCb->bktTbl[bktIdx].numAlloc = 0;
	regCb->bktTbl[bktIdx].numToBeFreed = 0;

	/* Update the total bucket size */
	regCb->bktSize += (size * numBlks);


} /* end of cmMmBktInit */


/*
*
*       Fun:   cmMmRegInit
*
*       Desc:  Configure the memory region for allocation. The function
*              registers the memory region with System Service by calling
*              SRegRegion.
*
*
*       Ret:   RET_OK     - successful,
*              RFAILED - unsuccessful.
*
*       Notes: The memory owner calls this function to initialize the memory
*              manager with the information of the memory region. Before
*              calling this function, the memory owner should allocate memory
*              for the memory region. The memory owner should also provide the
*              memory for the control block needed by the memory manager. The
*              memory owner should allocate the memory for the region control
*              block as cachable memory. This may increase the average
*              throughput in allocation and deallocation as the region control
*              block is mostly accessed by the CMM.
*
*       File:  cm_mem.c
*
*/
static int16_t cmMmRegInit
(
	CmMmRegCb   *regCb,
	SsMemRegCfg  *cfg
)
{
	Data *memAddr;
	uint16_t   bktIdx;
	uint16_t   lstMapIdx;

	/* Initial address of the memory region block */
	memAddr = regCb->start;

	/* Initialize the fields related to the bucket pool */
	regCb->bktMaxBlkSize = 0;
	regCb->bktSize = 0;

	if (cfg->numBkts)
	{
		/* Last bucket has the maximum size */
		regCb->bktMaxBlkSize = cfg->bkt[cfg->numBkts - 1].blkSize;

		/* Get the power of the bktQnSize */
		regCb->bktQnPwr = 0;
		while (!((MT_BKTQNSIZE >> regCb->bktQnPwr) & 0x01))
		{
			regCb->bktQnPwr++;
		}

		/* Initilaize the bktIndex of the map entries to FF */
		for (lstMapIdx = 0; lstMapIdx < CMM_MAX_MAP_ENT; lstMapIdx++)
		{
			regCb->mapTbl[lstMapIdx].bktIdx = 0xFF;
		}

		lstMapIdx = 0;
		for (bktIdx = 0; bktIdx < cfg->numBkts; bktIdx++)
		{
			/* Allocate the lock for the bucket pool */
			SInitLock(&(regCb->bktTbl[bktIdx].bktLock), SS_LOCK_THREAD_SHARE);
			cmMmBktInit(&memAddr, regCb, cfg, bktIdx, &lstMapIdx);
		}

		/* Used while freeing the bktLock in cmMmRegDeInit */
		regCb->numBkts = cfg->numBkts;
	}

	/*
	 * Initialize the heap pool if size the memory region region is more
	 * than the size of the bucket pool
	 */
	regCb->heapSize = 0;
	regCb->heapFlag = FALSE;

	/* Align the memory address */
	memAddr = (Data *)(CACHELINE_ALIGNED_ADDR(memAddr));

	regCb->heapSize = regCb->start + regCb->size - memAddr;

	/*
	 * Round the heap size so that the heap size is multiple
	 * of CMM_MINBUFSIZE
	 */
	regCb->heapSize -= (regCb->heapSize %  CMM_MINBUFSIZE);

	if (regCb->heapSize)
	{
		/* Allocate the lock for the heap pool */
		SInitLock(&regCb->heapCb.heapLock, SS_LOCK_THREAD_SHARE);

		regCb->heapFlag = TRUE;
		cmMmHeapInit(regCb->RegionId, memAddr, &(regCb->heapCb), regCb->heapSize);
	}

	regCb->used = TRUE;

	return(RET_OK);
} /* end of cmMmRegInit*/


static Size getConfigMemSize(const SsMemRegCfg* pRegionCfg)
{
	int i = 0;
	Size totalSize = 0;

	// buckets
	for (i = 0; i < pRegionCfg->numBkts; i++)
	{
		totalSize += pRegionCfg->bkt[i].blkSize * pRegionCfg->bkt[i].numBlks;
	}

	// heap
	totalSize += pRegionCfg->heapSize;

	totalSize = CACHELINE_ALIGNED_DATASIZE(totalSize);

	return(totalSize);
}

int16_t ThreadMemInit(char* name, pthread_t pt)
{
	uint32_t i;
	SsMemRegCfg *RegCfg;
	CmMmRegCb* RegCb;

	if (DomainNum >= DOMAIN_MAX_NUM - 1)
	{
		return RET_NOK;
	}

	if (strcmp(name, "Main") == 0)
	{
		/* initialize memory information */
		memset(&ThreadMemoryRegion, 0, sizeof(ThreadMemoryRegion));
	}

	/* implementation specific memory initialization */
	RegCfg = ScMemoryCfg;
	RegCb = &ThreadMemoryRegion[DomainNum];
	for (i = 0; i < MEM_CONFIG_NUM; i++, RegCfg++)
	{
		if (strncmp(name, RegCfg->name, strlen(RegCfg->name)) == 0)
		{
			break;
		}

		/* Thread name not found, using the default configuration */
		if (i == MEM_CONFIG_NUM - 1)
		{
			printf("Memory Configuration for Thread %s not found! Using default settings.\n", name);
		}
	}

	/* allocate space for the region */
	RegCb->size = getConfigMemSize(RegCfg);
	RegCb->start = (Data *)aligned_alloc(CACHELINE_SIZE, RegCb->size);
	if (RegCb->start == NULLP)
	{
		printf("Allocate Memory for Thread %s (%ld bytes) failed! ", name, RegCb->size);
		return(RET_NOK);
	}

	/* initialize the CMM */
	RegCb->RegionId = DomainNum;
	strncpy(RegCb->name, name, sizeof(RegCb->name) - 1);
	if (cmMmRegInit(RegCb, RegCfg) != RET_OK)
	{
		printf("cmMmRegInit region failed!\n");
		free(RegCb->start);
		return(RET_NOK);
	}
	RegCb->pt = pt;
	DomainNum++;

	return(RET_OK);
}

void ThreadMemDeinit(void)
{
	/*
		uint32_t i;

		for(i = 0; i < DomainNum; i++)
		{
			cmMmRegDeInit(&ThreadMemoryRegion[i]);
			free(ThreadMemoryRegion[i].start);
		}
		DomainNum = 0;
	*/
}

uint32_t ThreadMemGetNum(void)
{
	return DomainNum;
}

//#define SSI_DEBUG_OUTPUT

void* ssiMalloc(size_t size, const char* func, uint32_t line)
{
	void* ptrmem = NULL;
	Size s = size;
	CmMmRegCb* RegCb;

	if (size == 0)
	{
		return PTR_SIZE_0;
	}

	if (NULL == (RegCb = ssiGetThreadMemoryRegion()))
		return NULL;

	if (cmAlloc(RegCb, &s, (Data**)&ptrmem) == RET_OK)
	{
#ifdef SSI_DEBUG_OUTPUT
		printf("ssiMalloc succeed: Got addr %lX for %s:%d size %lu\n", (uint64_t)ptrmem, func, line, size);
#endif
		return ptrmem;
	}
	else
	{
		SCLogError(SC_ERR_MEM_ALLOC, "ssiMalloc failed, called from %s:%d, %lu bytes!",
			func, line, size);
		return NULL;
	}
}

void* ssiRealloc(void* ptr, size_t size, const char* func, uint32_t line)
{
	void* ptrmem = NULL;
	Size s = size, old_s = 0;
	MemBlockHeader *memHeader;
	CmMmRegCb* RegCurCb, *RegSourceCb;

	if (ptr == NULL)
	{
		return ssiMalloc(size, func, line);
	}
	if (s == 0)
	{
		ssiFree(ptr, func, line);
		return NULL;
	}
	if (NULL == (RegCurCb = ssiGetThreadMemoryRegion()))
		return NULL;

	memHeader = (MemBlockHeader*)(ptr - sizeof(MemBlockHeader));
	if (memHeader->RegionId < 0 || memHeader->RegionId >= DomainNum)
		return NULL;
	RegSourceCb = &ThreadMemoryRegion[memHeader->RegionId];

	/* Check if the memory block is from the memory region */
	if ((Data*)ptr < RegSourceCb->start
		|| (Data*)ptr >= RegSourceCb->start + RegSourceCb->size)
	{
		/* Out of our memory region, just use system free() */
#ifdef SSI_DEBUG_OUTPUT
		printf("ssiRealloc addr %lX called from %s:%d, out of memory region, trying realloc()!\n", (uint64_t)ptr, func, line);
#endif
		return realloc(ptr, size);
	}

	if (cmAlloc(RegCurCb, &s, (Data**)&ptrmem) == RET_OK)
	{
		/* Get memory size */
		old_s = memHeader->size;
		memcpy(ptrmem, ptr, s < old_s ? s : old_s);

		if (RegSourceCb->RegionId != RegCurCb->RegionId)
		{
			//			printf("Thread %s, releasing memory from %s, %s:%d: %u bytes\n", RegCurCb->name, RegSourceCb->name, func, line, memHeader->size);
		}

		/* We should free */
		if (cmFree(RegSourceCb, (Data*)ptr, &old_s) != RET_OK)
		{
			SCLogError(SC_ERR_MEM_ALLOC, "ssiRealloc failed, old ptr %lX, new size %lu, called from %s:%d: free old memory failed!\n", (uint64_t)ptr, size, func, line);
			cmFree(RegCurCb, (Data*)ptrmem, &s);
			return NULL;
		}
#ifdef SSI_DEBUG_OUTPUT
		printf("ssiRealloc succeed: Got addr %lX for %s:%d ptr %lX, old size %lu, new size %lu\n", (uint64_t)ptrmem, func, line, (uint64_t)ptr, old_s, size);
#endif
		return ptrmem;
	}
	else
	{
		SCLogError(SC_ERR_MEM_ALLOC, "ssiRealloc failed, old ptr %lX, new size %lu, called from %s:%d: allocate new memory failed!\n", (uint64_t)ptr, size, func, line);
		return NULL;
	}
}

void* ssiCalloc(size_t nm, size_t size, const char* func, uint32_t line)
{
	void* ptrmem = NULL;
	Size s = nm * size;
	CmMmRegCb* RegCb;

	if (s == 0)
		return PTR_SIZE_0;
	if (NULL == (RegCb = ssiGetThreadMemoryRegion()))
		return NULL;

	if (cmAlloc(RegCb, &s, (Data**)&ptrmem) == RET_OK)
	{
#ifdef SSI_DEBUG_OUTPUT
		printf("ssiCalloc succeed: Got addr %lX for %s:%d nmem %lu size %lu\n", (uint64_t)ptrmem, func, line, nm, size);
#endif
		memset(ptrmem, 0, nm * size);
		return ptrmem;
	}
	else
	{
		SCLogError(SC_ERR_MEM_ALLOC, "ssiCalloc failed, called from %s:%d, nmem %lu size %lu, total size %lu bytes!",
			func, line, nm, size, s);
		return NULL;
	}
}

char* ssiStrdup(const char* s, const char* func, uint32_t line)
{
	void* ptrmem = NULL;
	Size size = strlen(s) + 1;
	CmMmRegCb* RegCb;

	if (NULL == (RegCb = ssiGetThreadMemoryRegion()))
		return NULL;

	if (cmAlloc(RegCb, &size, (Data**)&ptrmem) == RET_OK)
	{
		memcpy(ptrmem, s, size);
#ifdef SSI_DEBUG_OUTPUT
		printf("ssiStrdup succeed: Got addr %lX for %s:%d size %lu\n", (uint64_t)ptrmem, func, line, strlen(s) + 1);
#endif
		return (char*)ptrmem;
	}
	else
	{
		SCLogError(SC_ERR_MEM_ALLOC, "ssiStrdup failed, called from %s:%d, %lu bytes!",
			func, line, size);
		return NULL;
	}
	return NULL;
}

void ssiFree(void* ptr, const char* func, uint32_t line)
{
	Size size = 0;
	MemBlockHeader *memHeader;
	CmMmRegCb* RegSourceCb;
	CmMmRegCb* RegCurCb = ssiGetThreadMemoryRegion();

	if (!ptr || ptr == PTR_SIZE_0)
		return;
	memHeader = (MemBlockHeader*)(ptr - sizeof(MemBlockHeader));
	if (memHeader->RegionId < 0 || memHeader->RegionId >= DomainNum)
		return;
	RegSourceCb = &ThreadMemoryRegion[memHeader->RegionId];

	/* Check if the memory block is from the memory region */
	if ((Data*)ptr < RegSourceCb->start
		|| (Data*)ptr >= RegSourceCb->start + RegSourceCb->size)
	{

		/* Out of our memory region, just use system free() */
		printf("Thread %s: ssiFree addr %lx called from %s, %s:%d, out of memory region, trying free()!\n", RegCurCb->name, (uint64_t)ptr, RegSourceCb->name, func, line);
		free(ptr);
		return;
	}

	if (RegSourceCb->RegionId != RegCurCb->RegionId)
	{
		//		printf("Thread %s, releasing memory from %s, %s:%d: %u bytes\n", RegCurCb->name, RegSourceCb->name, func, line, memHeader->size);
	}

	if (cmFree(RegSourceCb, (Data*)ptr, &size) == RET_OK)
	{
#ifdef SSI_DEBUG_OUTPUT
		printf("ssiFree succeed: addr %lX called from %s:%d size %lu\n", (uint64_t)ptr, func, line, size);
#endif
	}
	else
	{
		printf("ssiFree failed, addr %lX called from %s:%d!\n", (uint64_t)ptr, func, line);
	}
}
#endif

