/*
 * IMPORTANT: READ BEFORE DOWNLOADING, COPYING, INSTALLING OR USING. By
 * downloading, copying, installing or using the software you agree to
 * this license. If you do not agree to this license, do not download,
 * install, copy or use the software.
 *
 * Intel License Agreement
 *
 * Copyright (c) 2000, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * -Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 *
 * -Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the
 *  following disclaimer in the documentation and/or other materials
 *  provided with the distribution.
 *
 * -The name of Intel Corporation may not be used to endorse or
 *  promote products derived from this software
 *  without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
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
extern void     set_debug(const char *);
extern void     iscsi_trace(const int, const char *, const int, const char *,
			    ...);
extern void     iscsi_trace_warning(const char *, const int, const char *, ...);
extern void     iscsi_trace_error(const char *, const int, const char *, ...);
extern void     iscsi_print_buffer(uint8_t *, const size_t);

/*
 * Socket Abstraction
 */

extern int      iscsi_sock_send_header_and_data(GConn *,
						const void *, unsigned,
						const void *, unsigned, int);
extern int      modify_iov(struct iovec **, int *, uint32_t, uint32_t);

extern void     cdb2lba(uint32_t *, uint16_t *, uint8_t *);
extern void     lba2cdb(uint8_t *, uint32_t *, uint16_t *);

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

extern int      HexTextToData(const char *, uint32_t, uint8_t *, uint32_t);
extern int      HexDataToText(uint8_t *, uint32_t, char *, uint32_t);
extern void     GenRandomData(uint8_t *, uint32_t);

/* this is the maximum number of iovecs which we can use in iscsi_sock_send_header_and_data */
#ifndef ISCSI_MAX_IOVECS
#define ISCSI_MAX_IOVECS        32
#endif

extern int      allow_netmask(const char *, const char *);

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
extern size_t   strlcpy(char *, const char *, size_t);
#endif

#endif /* _ISCSIUTIL_H_ */
