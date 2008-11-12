/*
 * IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING. By downloading, copying, installing or
 * using the software you agree to this license. If you do not agree to this license, do not download, install,
 * copy or use the software.
 *
 * Intel License Agreement
 *
 * Copyright (c) 2000, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that
 * the following conditions are met:
 *
 * -Redistributions of source code must retain the above copyright notice, this list of conditions and the
 *  following disclaimer.
 *
 * -Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *  following disclaimer in the documentation and/or other materials provided with the distribution.
 *
 * -The name of Intel Corporation may not be used to endorse or promote products derived from this software
 *  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _ISCSIUTIL_H_
#define _ISCSIUTIL_H_

#include "itd-config.h"

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnet.h>

/*
 * Debugging Levels
 */

#define TRACE_NET_DEBUG      0x00000001
#define TRACE_NET_BUFF       0x00000002
#define TRACE_NET_IOV        0x00000004
#define TRACE_NET_ALL        (TRACE_NET_DEBUG|TRACE_NET_BUFF|TRACE_NET_IOV)

#define TRACE_ISCSI_DEBUG    0x00000010
#define TRACE_ISCSI_CMD      0x00000020
#define TRACE_ISCSI_ARGS     0x00000040
#define TRACE_ISCSI_PARAM    0x00000080
#define TRACE_ISCSI_ALL      (TRACE_ISCSI_DEBUG|TRACE_ISCSI_ARGS|TRACE_ISCSI_PARAM|TRACE_ISCSI_CMD)

#define TRACE_SCSI_DEBUG     0x00000100
#define TRACE_SCSI_CMD       0x00000200
#define TRACE_SCSI_DATA      0x00000400
#define TRACE_SCSI_ARGS      0x00000800
#define TRACE_SCSI_ALL       (TRACE_SCSI_DEBUG|TRACE_SCSI_CMD|TRACE_SCSI_DATA|TRACE_SCSI_ARGS)

#define TRACE_DEBUG          0x00001000
#define TRACE_HASH           0x00002000
#define TRACE_SYNC           0x00004000
#define TRACE_QUEUE          0x00008000
#define TRACE_WARN           0x00010000
#define TRACE_MEM            0x00020000

#define TRACE_OSD            0x00040000
#define TRACE_OSDFS          0x00080000
#define TRACE_OSDSO          0x00100000
#define TRACE_ALL            0xffffffff

/*
 * Set debugging level here. Turn on debugging in Makefile.
  */
extern uint32_t iscsi_debug_level;

/*
 * Debugging Functions
 */
void set_debug(const char *);
void iscsi_trace(const int, const char *, const int, const char *, ...);
void iscsi_trace_warning(const char *, const int, const char *, ...);
void iscsi_trace_error(const char *, const int, const char *, ...);
void iscsi_print_buffer(const char *, const size_t);

/* Spin locks */

typedef pthread_mutex_t iscsi_spin_t;

int iscsi_spin_init(iscsi_spin_t *);
int iscsi_spin_lock(iscsi_spin_t *);
int iscsi_spin_unlock(iscsi_spin_t *);
int iscsi_spin_lock_irqsave(iscsi_spin_t *, uint32_t *);
int iscsi_spin_unlock_irqrestore(iscsi_spin_t *, uint32_t *);
int iscsi_spin_destroy(iscsi_spin_t *);

/*
 * End of ISCSI spin routines
 */

/*
 * Queuing
 */

typedef struct iscsi_queue_t {
	int head;
	int tail;
	int count;
	void **elem;
	int depth;
	iscsi_spin_t lock;
} iscsi_queue_t;

int iscsi_queue_init(iscsi_queue_t *, int);
void iscsi_queue_destroy(iscsi_queue_t *);
int iscsi_queue_insert(iscsi_queue_t *, void *);
void *iscsi_queue_remove(iscsi_queue_t *);
int iscsi_queue_depth(iscsi_queue_t *);
int iscsi_queue_full(iscsi_queue_t *);

/*
 * Socket Abstraction
 */

/* Turning off Nagle's Algorithm doesn't always seem to work, */
/* so we combine two messages into one when the second's size */
/* is less than or equal to ISCSI_SOCK_HACK_CROSSOVER. */

#define ISCSI_SOCK_HACK_CROSSOVER    1024
#define ISCSI_SOCK_CONNECT_NONBLOCK  0
#define ISCSI_SOCK_CONNECT_TIMEOUT   1
#define ISCSI_SOCK_MSG_BYTE_ALIGN    4

int iscsi_sock_shutdown(int, int);
int iscsi_sock_close(int);
int iscsi_sock_msg(int, int, unsigned, void *, int);
int iscsi_sock_send_header_and_data(GConn *,
				    const void *, unsigned,
				    const void *, unsigned, int);
int modify_iov(struct iovec **, int *, uint32_t, uint32_t);

void cdb2lba(uint32_t *, uint16_t *, uint8_t *);
void lba2cdb(uint8_t *, uint32_t *, uint16_t *);

/*
 * Mutexes
 */

typedef pthread_mutex_t iscsi_mutex_t;

int iscsi_mutex_init(iscsi_mutex_t *);
int iscsi_mutex_lock(iscsi_mutex_t *);
int iscsi_mutex_unlock(iscsi_mutex_t *);
int iscsi_mutex_destroy(iscsi_mutex_t *);

#define ISCSI_LOCK(M, ELSE)	do {					\
	if (iscsi_mutex_lock(M) != 0) {					\
		iscsi_trace_error(__FILE__, __LINE__, "iscsi_mutex_lock() failed\n");	\
		ELSE;							\
	}								\
} while (/* CONSTCOND */ 0)

#define ISCSI_UNLOCK(M, ELSE)	do {					\
	if (iscsi_mutex_unlock(M) != 0) {				\
		iscsi_trace_error(__FILE__, __LINE__, "iscsi_mutex_unlock() failed\n");	\
		ELSE;							\
	}								\
} while (/* CONSTCOND */ 0)

#define ISCSI_MUTEX_INIT(M, ELSE) do {					\
	if (iscsi_mutex_init(M) != 0) {					\
		iscsi_trace_error(__FILE__, __LINE__, "iscsi_mutex_init() failed\n");	\
		ELSE;							\
	}								\
} while (/* CONSTCOND */ 0)

#define ISCSI_MUTEX_DESTROY(M, ELSE) do {				\
	if (iscsi_mutex_destroy(M) != 0) {				\
		iscsi_trace_error(__FILE__, __LINE__, "iscsi_mutex_destroy() failed\n");	\
		ELSE;							\
	}								\
} while (/* CONSTCOND */ 0)

/*
 * Pre/Post condition checking
 */

#define NO_CLEANUP {}
#define RETURN_GREATER(NAME, V1, V2, CU, RC)                         \
if ((V1)>(V2)) {                                                     \
  iscsi_trace_error(__FILE__, __LINE__, "Bad \"%s\": %u > %u.\n", NAME, (unsigned)V1, (unsigned)V2); \
  CU;                                                                \
  return RC;                                                         \
}

#define RETURN_NOT_EQUAL(NAME, V1, V2, CU, RC)                       \
if ((V1)!=(V2)) {                                                    \
  iscsi_trace_error(__FILE__, __LINE__, "Bad \"%s\": Got %u expected %u.\n", NAME, V1, V2);    \
  CU;                                                                \
  return RC;                                                         \
}

#define WARN_NOT_EQUAL(NAME, V1, V2)                                 \
if ((V1)!=(V2)) {                                                    \
  iscsi_trace_warning(__FILE__, __LINE__, "Bad \"%s\": Got %u expected %u.\n", NAME, V1, V2);  \
}

#define RETURN_EQUAL(NAME, V1, V2, CU, RC)                           \
if ((V1)==(V2)) {                                                    \
  iscsi_trace_error(__FILE__, __LINE__, "Bad \"%s\": %u == %u.\n", NAME, V1, V2);              \
  CU;                                                                \
  return RC;                                                         \
}

/*
 * Misc. Functions
 */

extern uint32_t iscsi_atoi(char *);
extern int HexTextToData(const char *, uint32_t, uint8_t *, uint32_t);
extern int HexDataToText(uint8_t *, uint32_t, char *, uint32_t);
extern void GenRandomData(uint8_t *, uint32_t);

/* this is the maximum number of iovecs which we can use in iscsi_sock_send_header_and_data */
#ifndef ISCSI_MAX_IOVECS
#define ISCSI_MAX_IOVECS        32
#endif

enum {
	/* used in iscsi_sock_msg() */
	Receive = 0,
	Transmit = 1
};

int allow_netmask(const char *, const char *);

#define NEWARRAY(type,ptr,size,where,action) do {			\
	if ((ptr = (type *) calloc(sizeof(type), (unsigned)(size))) == NULL) { \
		fprintf(stderr, "%s: can't allocate %lu bytes\n", \
			where, (unsigned long)(size * sizeof(type)));	\
		action;							\
	}								\
} while( /* CONSTCOND */ 0)

#define DEFINE_ARRAY(name, type)					\
typedef struct name {							\
	uint32_t	c;						\
	uint32_t	size;						\
	type	       *v;						\
} name

#ifndef HAVE_STRLCPY
size_t strlcpy(char *, const char *, size_t);
#endif
#ifndef HAVE_STRLCAT
extern size_t strlcat(char *dst, const char *src, size_t siz);
#endif

#endif /* _ISCSIUTIL_H_ */
