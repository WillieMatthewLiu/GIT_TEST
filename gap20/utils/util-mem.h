/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Utility Macros for memory management
 *
 * \todo Add wrappers for functions that allocate/free memory here.
 * Currently we have malloc, calloc, realloc, strdup and free,
 * but there are more.
 */

#ifndef __UTIL_MEM_H__
#define __UTIL_MEM_H__

//#include "util-atomic.h"

#if defined(_WIN32) || defined(__WIN32)
#include "mm_malloc.h"
#endif

//SC_ATOMIC_EXTERN(unsigned int, engine_stage);

/* Use this only if you want to debug memory allocation and free()
 * It will log a lot of lines more, so think that is a performance killer */

/* Uncomment this if you want to print memory allocations and free's() */
//#define DBG_MEM_ALLOC
//#define USER_MEM_ALLOC

#ifdef USER_MEM_ALLOC
extern void* ssiMalloc(size_t size, const char* func, uint32_t line);
#define SCMalloc(a)		ssiMalloc(a, __FUNCTION__, __LINE__)

extern void* ssiRealloc(void* ptr, size_t size, const char* func, uint32_t line);
#define SCRealloc(x, a)		ssiRealloc(x, a, __FUNCTION__, __LINE__)

extern void* ssiCalloc(size_t nm, size_t size, const char* func, uint32_t line);
#define SCCalloc(nm, a)		ssiCalloc(nm, a, __FUNCTION__, __LINE__)

extern char* ssiStrdup(const char* s, const char* func, uint32_t line);
#define SCStrdup(s)		ssiStrdup(s, __FUNCTION__, __LINE__)

extern void ssiFree(void* prt, const char* func, uint32_t line);
#define SCFree(a)		ssiFree(a, __FUNCTION__, __LINE__)

extern int16_t ThreadMemInit(char* name, pthread_t pt);
extern int16_t SRegInfoShow(char* show_buf, int32_t max_buf_len, int32_t region_id);
extern void ThreadMemDeinit(void);
extern uint32_t ThreadMemGetNum(void);

#else /* USER_MEM_ALLOC */

#ifdef DBG_MEM_ALLOC

/* Uncomment this if you want to print mallocs at the startup (recommended) */
#define DBG_MEM_ALLOC_SKIP_STARTUP

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = malloc((a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCMalloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
        if (SC_ATOMIC_GET(engine_stage) == SOUTHWEST_ENGINE_INIT) {\
            SCLogError( "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a); \
    if (print_mem_flag == 1) {                               \
        SCLogInfo("SCMalloc return at %p of size %"PRIuMAX, \
            ptrmem, (uintmax_t)(a)); \
    }                                \
    (void*)ptrmem; \
})

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = realloc((x), (a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCRealloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)(a)); \
        if (SC_ATOMIC_GET(engine_stage) == SOUTHWEST_ENGINE_INIT) {\
            SCLogError( "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a); \
    if (print_mem_flag == 1) {                                         \
        SCLogInfo("SCRealloc return at %p (old:%p) of size %"PRIuMAX, \
            ptrmem, (x), (uintmax_t)(a)); \
    }                                     \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    \
    ptrmem = calloc((nm), (a)); \
    if (ptrmem == NULL && (a) > 0) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCCalloc failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)a); \
        if (SC_ATOMIC_GET(engine_stage) == SOUTHWEST_ENGINE_INIT) {\
            SCLogError( "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += (a)*(nm); \
    if (print_mem_flag == 1) {                                          \
        SCLogInfo("SCCalloc return at %p of size %"PRIuMAX" (nm) %"PRIuMAX, \
            ptrmem, (uintmax_t)(a), (uintmax_t)(nm)); \
    }                                                 \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    extern size_t global_mem; \
    extern uint8_t print_mem_flag; \
    size_t len = strlen((a)); \
    \
    ptrmem = strdup((a)); \
    if (ptrmem == NULL) { \
        SCLogError(SC_ERR_MEM_ALLOC, "SCStrdup failed: %s, while trying " \
            "to allocate %"PRIuMAX" bytes", strerror(errno), (uintmax_t)len); \
        if (SC_ATOMIC_GET(engine_stage) == SOUTHWEST_ENGINE_INIT) {\
            SCLogError( "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    \
    global_mem += len; \
    if (print_mem_flag == 1) {                              \
        SCLogInfo("SCStrdup return at %p of size %"PRIuMAX, \
            ptrmem, (uintmax_t)len); \
    }                                \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    extern uint8_t print_mem_flag; \
    if (print_mem_flag == 1) {          \
        SCLogInfo("SCFree at %p", (a)); \
    }                                   \
    free((a)); \
})
#if 0
#elif defined(HAVE_MEMORY_H)
#include "memory.h"
#include "memtypes.h"

#define SCMalloc(a)     XMALLOC(MTYPE_TMP, (a))
#define SCRealloc(x, a) XREALLOC(MTYPE_TMP, (x), (a))
#define SCCalloc(nm, a) XCALLOC(MTYPE_TMP, (nm)*(a))
#define SCStrdup(a)     XSTRDUP(MTYPE_TMP, (a))
#define SCFree(a)       XFREE(MTYPE_TMP, (a))
#endif
#else /* !DBG_MEM_ALLOC */

#define SCMalloc(a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = malloc((a)); \
    (void*)ptrmem; \
})

#define SCRealloc(x, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = realloc((x), (a)); \
    (void*)ptrmem; \
})

#define SCCalloc(nm, a) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = calloc((nm), (a)); \
    (void*)ptrmem; \
})

#define SCStrdup(a) ({ \
    char *ptrmem = NULL; \
    \
    ptrmem = strdup((a)); \
    (void*)ptrmem; \
})

#define SCFree(a) ({ \
    free(a); \
})

#if defined(__WIN32) || defined(_WIN32)

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
	ptrmem = _mm_malloc((a), (b)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SOUTHWEST_ENGINE_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)(a), (uintmax_t)(b)); \
            SCLogError( "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
#define SCFreeAligned(a) ({ \
    _mm_free(a); \
})

#else /* !win */

/** \brief wrapper for allocing aligned mem
 *  \param a size
 *  \param b alignement
 */
#define SCMallocAligned(a, b) ({ \
    void *ptrmem = NULL; \
    \
    ptrmem = _mm_malloc((a), (b)); \
    if (ptrmem == NULL) { \
        if (SC_ATOMIC_GET(engine_stage) == SOUTHWEST_ENGINE_INIT) {\
            SCLogError(SC_ERR_MEM_ALLOC, "SCMallocAligned(posix_memalign) failed: %s, while trying " \
                "to allocate %"PRIuMAX" bytes, alignment %"PRIuMAX, strerror(errno), (uintmax_t)a, (uintmax_t)b); \
            SCLogError( "Out of memory. The engine cannot be initialized. Exiting..."); \
            exit(EXIT_FAILURE); \
        } \
    } \
    (void*)ptrmem; \
})

/** \brief Free aligned memory
 *
 * Not needed for mem alloc'd by posix_memalign,
 * but for possible future use of _mm_malloc needing
 * _mm_free.
 */
#define SCFreeAligned(a) ({ \
    _mm_free((a)); \
})

#endif /* __WIN32 */

#endif /* DBG_MEM_ALLOC */

#endif /* USER_MEM_ALLOC */

#endif /* __UTIL_MEM_H__ */

