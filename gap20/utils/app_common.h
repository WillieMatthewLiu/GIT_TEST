
#ifndef _APP_COMMON_H_
#define _APP_COMMON_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#define __USE_GNU
#endif
#if HAVE_CONFIG_H
#include <config.h>
#endif

#if HAVE_STDIO_H
#include <stdio.h>
#endif

#if HAVE_STDINT_h
#include <stdint.h>
#endif

#if HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#if HAVE_ERRNO_H
#include <errno.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#if HAVE_LIMITS_H
#include <limits.h>
#endif

#if HAVE_CTYPE_H
#include <ctype.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#endif

#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#if HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif

#if HAVE_SYSCALL_H
#include <syscall.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h> /* for gettid(2) */
#endif

#if HAVE_SCHED_H
#include <sched.h>     /* for sched_setaffinity(2) */
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#ifdef OS_WIN32
#include "win32-syslog.h"
#endif /* OS_WIN32 */
#endif /* HAVE_SYSLOG_H */

#ifdef OS_WIN32
#include "win32-misc.h"
#include "win32-service.h"
#endif /* OS_WIN32 */

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_POLL_H
#include <poll.h>
#endif

#if HAVE_SYS_SIGNAL_H
#include <sys/signal.h>
#endif

#if HAVE_SIGNAL_H
#include <signal.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <sys/un.h>

#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#if __CYGWIN__
#if !defined _X86_ && !defined __x86_64
#define _X86_
#endif
#endif

#ifdef HAVE_WINDOWS_H
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501
#endif
#include <windows.h>
#endif

#ifdef HAVE_W32API_WINBASE_H
#include <w32api/winbase.h>
#endif

#if !__CYGWIN__
#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif
#endif /* !__CYGWIN__ */

#ifdef HAVE_ASSERT_H
#include <assert.h>
#define BUG_ON(x) assert(!(x))
#else
#define BUG_ON(x)
#endif

/* we need this to stringify the defines which are supplied at compiletime see:
   http://gcc.gnu.org/onlinedocs/gcc-3.4.1/cpp/Stringification.html#Stringification */
#define xstr(s) str(s)
#define str(s) #s

   /** type for the internal signature id. Since it's used in the matching engine
	*  extensively keeping this as small as possible reduces the overall memory
	*  footprint of the engine. Set to uint32_t if the engine needs to support
	*  more than 64k sigs. */
#define SigIntId uint16_t
	//#define SigIntId uint32_t

	/** same for pattern id's */
#define PatIntId uint16_t

/** FreeBSD does not define __WORDSIZE, but it uses __LONG_BIT */
#ifndef __WORDSIZE
#ifdef __LONG_BIT
#define __WORDSIZE __LONG_BIT
#else
#ifdef LONG_BIT
#define __WORDSIZE LONG_BIT
#endif
#endif
#endif

/** Windows does not define __WORDSIZE, but it uses __X86__ */
#ifndef __WORDSIZE
#if defined(__X86__) || defined(_X86_)
#define __WORDSIZE 32
#else
#if defined(__X86_64__) || defined(_X86_64_)
#define __WORDSIZE 64
#endif
#endif

#ifndef __WORDSIZE
#define __WORDSIZE 32
#endif
#endif

/** darwin doesn't defined __BYTE_ORDER and friends, but BYTE_ORDER */
#ifndef __BYTE_ORDER
#ifdef BYTE_ORDER
#define __BYTE_ORDER BYTE_ORDER
#endif
#endif

#ifndef __LITTLE_ENDIAN
#ifdef LITTLE_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#endif
#endif

#ifndef __BIG_ENDIAN
#ifdef BIG_ENDIAN
#define __BIG_ENDIAN BIG_ENDIAN
#endif
#endif






#define DBG_MSG 		0
#if DBG_MSG
#define debug_msg_printf(format, arg...)	printf("DEBUG: " format "\n", ## arg)
#else
#define debug_msg_printf(format, arg, ...)	do {} while (0)	
#endif


#define TRUE 	1
#define FALSE  	0
#define countof(_Array) (sizeof(_Array) / sizeof(_Array[0]))

#define unused(x) {x=x;}

#define SCMutex pthread_mutex_t
#define SCMutexAttr pthread_mutexattr_t
#define SCMutexDestroy pthread_mutex_destroy

#define SCMutexInit(mut, mutattr ) pthread_mutex_init(mut, mutattr)
#define SCMutexLock(mut) pthread_mutex_lock(mut)
#define SCMutexTrylock(mut) pthread_mutex_trylock(mut)
#define SCMutexUnlock(mut) pthread_mutex_unlock(mut)

#define ALIGN(x, a) (((x)+(a)-1)&(~((a)-1)))

enum APP_ERROR_CODE {
	APP_ERROR_NONE,



	APP_ERROR_MAX
};


#include <zebra.h>
//////////////////////////////////////////////////////////////////////////
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <event2/event.h>
#include <event2/thread.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <resolv.h>
#include <semaphore.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#define closesocket close
#define strtok_s strtok_r

#include "util-array.h"
#include "util-list.h"
#include "util-hashlist.h"
#include "util-mem.h"
#include "util-debug.h"
//////////////////////////////////////////////////////////////////////////

#define HAVE_SSL_NONBLOCK
#warning "this file will delete, use lib/zebra.h instead of it"
#endif // _APP_COMMON_H_


