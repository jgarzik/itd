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

#include "itd-config.h"

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_NETINET_TCP_H
#include <netinet/tcp.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_POLL_H
#include <poll.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <unistd.h>
#include <glib.h>

#include "iscsi.h"
#include "iscsiutil.h"

#ifndef __UNCONST
#define __UNCONST(a)    ((void *)(unsigned long)(const void *)(a))
#endif

#ifndef _DIAGASSERT
#  ifndef __static_cast
#  define __static_cast(x,y) (x)y
#  endif
#define _DIAGASSERT(e) (__static_cast(void,0))
#endif

static const char *scsi_cmd_str[0xff] =
{
	[0x00] = "TEST_UNIT_READY",
	[0x01] = "REZERO_UNIT",
	[0x03] = "REQUEST_SENSE",
	[0x04] = "FORMAT_UNIT",
	[0x05] = "READ_BLOCK_LIMITS",
	[0x07] = "REASSIGN_BLOCKS",
	[0x07] = "INITIALIZE_ELEMENT_STATUS",
	[0x08] = "READ_6",
	[0x0a] = "WRITE_6",
	[0x0b] = "SEEK_6",
	[0x0f] = "READ_REVERSE",
	[0x10] = "WRITE_FILEMARKS",
	[0x11] = "SPACE",
	[0x12] = "INQUIRY",
	[0x14] = "RECOVER_BUFFERED_DATA",
	[0x15] = "MODE_SELECT",
	[0x16] = "RESERVE",
	[0x17] = "RELEASE",
	[0x18] = "COPY",
	[0x19] = "ERASE",
	[0x1a] = "MODE_SENSE",
	[0x1b] = "START_STOP",
	[0x1c] = "RECEIVE_DIAGNOSTIC",
	[0x1d] = "SEND_DIAGNOSTIC",
	[0x1e] = "ALLOW_MEDIUM_REMOVAL",
	[0x24] = "SET_WINDOW",
	[0x25] = "READ_CAPACITY",
	[0x28] = "READ_10",
	[0x2a] = "WRITE_10",
	[0x2b] = "SEEK_10",
	[0x2b] = "POSITION_TO_ELEMENT",
	[0x2e] = "WRITE_VERIFY",
	[0x2f] = "VERIFY",
	[0x30] = "SEARCH_HIGH",
	[0x31] = "SEARCH_EQUAL",
	[0x32] = "SEARCH_LOW",
	[0x33] = "SET_LIMITS",
	[0x34] = "PRE_FETCH",
	[0x34] = "READ_POSITION",
	[0x35] = "SYNCHRONIZE_CACHE",
	[0x36] = "LOCK_UNLOCK_CACHE",
	[0x37] = "READ_DEFECT_DATA",
	[0x38] = "MEDIUM_SCAN",
	[0x39] = "COMPARE",
	[0x3a] = "COPY_VERIFY",
	[0x3b] = "WRITE_BUFFER",
	[0x3c] = "READ_BUFFER",
	[0x3d] = "UPDATE_BLOCK",
	[0x3e] = "READ_LONG",
	[0x3f] = "WRITE_LONG",
	[0x40] = "CHANGE_DEFINITION",
	[0x41] = "WRITE_SAME",
	[0x42] = "UNMAP",
	[0x43] = "READ_TOC",
	[0x4c] = "LOG_SELECT",
	[0x4d] = "LOG_SENSE",
	[0x53] = "XDWRITEREAD_10",
	[0x55] = "MODE_SELECT_10",
	[0x56] = "RESERVE_10",
	[0x57] = "RELEASE_10",
	[0x5a] = "MODE_SENSE_10",
	[0x5e] = "PERSISTENT_RESERVE_IN",
	[0x5f] = "PERSISTENT_RESERVE_OUT",
	[0x7f] = "VARIABLE_LENGTH_CMD",
	[0xa0] = "REPORT_LUNS",
	[0xa3] = "MAINTENANCE_IN",
	[0xa4] = "MAINTENANCE_OUT",
	[0xa5] = "MOVE_MEDIUM",
	[0xa6] = "EXCHANGE_MEDIUM",
	[0xa8] = "READ_12",
	[0xaa] = "WRITE_12",
	[0xae] = "WRITE_VERIFY_12",
	[0xb0] = "SEARCH_HIGH_12",
	[0xb1] = "SEARCH_EQUAL_12",
	[0xb2] = "SEARCH_LOW_12",
	[0xb8] = "READ_ELEMENT_STATUS",
	[0xb6] = "SEND_VOLUME_TAG",
	[0xea] = "WRITE_LONG_2",
	[0x88] = "READ_16",
	[0x8a] = "WRITE_16",
	[0x8f] = "VERIFY_16",
	[0x93] = "WRITE_SAME_16",
	[0x9e] = "SERVICE_ACTION_IN",
	[0x85] = "ATA_16",
	[0xa1] = "ATA_12",
};

const char *sopstr(uint8_t op)
{
	if (scsi_cmd_str[op])
		return scsi_cmd_str[op];

	return "(unknown)";
}

/* debugging levels */
void set_debug(const char *level)
{
	if (strcmp(level, "net") == 0) {
		iscsi_debug_level |= TRACE_NET_ALL;
	} else if (strcmp(level, "iscsi") == 0) {
		iscsi_debug_level |= TRACE_ISCSI_ALL;
	} else if (strcmp(level, "scsi") == 0) {
		iscsi_debug_level |= TRACE_SCSI_ALL;
	} else if (strcmp(level, "osd") == 0) {
		iscsi_debug_level |= TRACE_OSD;
	} else if (strcmp(level, "all") == 0) {
		iscsi_debug_level |= TRACE_ALL;
	}
}

void
iscsi_trace(const int trace, const char *f, const int line, const char *fmt,
	    ...)
{
	va_list         vp;
	char            buf[8192];

	if (iscsi_debug_level & trace) {
		va_start(vp, fmt);
		vsnprintf(buf, sizeof(buf), fmt, vp);
		printf("pid %ld:%s:%d: %s", (long) getpid(), f, line, buf);
		va_end(vp);
	}
}

void iscsi_trace_warning(const char *f, const int line, const char *fmt, ...)
{
	va_list         vp;
	char            buf[8192];

	if (iscsi_debug_level & TRACE_WARN) {
		va_start(vp, fmt);
		vsnprintf(buf, sizeof(buf), fmt, vp);
		printf("pid %ld:%s:%d: ***WARNING*** %s",
		       (long) getpid(), f, line, buf);
		va_end(vp);
	}
}

void iscsi_trace_error(const char *f, const int line, const char *fmt, ...)
{
	va_list         vp;
	char            buf[8192];

	va_start(vp, fmt);
	vsnprintf(buf, sizeof(buf), fmt, vp);
	va_end(vp);
	printf("pid %ld:%s:%d: ***ERROR*** %s", (long) getpid(), f, line, buf);
#  ifdef HAVE_SYSLOG
	syslog(LOG_ERR, "pid %ld:%s:%d: ***ERROR*** %s", (long) getpid(), f, line, buf);
#  endif /* HAVE_SYSLOG */
}

void iscsi_print_buffer(uint8_t * buf, const size_t len)
{
	int             i;

	if (iscsi_debug_level & TRACE_NET_BUFF) {
		for (i = 0; i < len; i++) {
			if (i % 4 == 0) {
				if (i) {
					printf("\n");
				}
				printf("%4i:", i);
			}
			printf("%2x ", (uint8_t) (buf)[i]);
		}
		if ((len + 1) % 32) {
			printf("\n");
		}
	}
}

static GTrashStack *free_headers;

void *header_get(void)
{
	void *mem;

	mem = g_trash_stack_pop(&free_headers);
	if (mem)
		return mem;

	return malloc(ISCSI_HEADER_LEN);
}

void header_put(void *mem)
{
	g_trash_stack_push(&free_headers, mem);
}

bool hdr_cb_free(struct atcp_wr_state *wst, void *cb_data, bool done)
{
	header_put(cb_data);
	return false;
}

void hdrs_free_all(void)
{
	while (1) {
		void *mem;

		mem = g_trash_stack_pop(&free_headers);
		if (!mem)
			break;

		free(mem);
	}
}

void send_padding(struct atcp_wr_state *st, unsigned int len_out)
{
	int pad_len;
	static const char pad_buf[4] = { 0, 0, 0, 0 };

	pad_len = padding_bytes(len_out);
	if (!pad_len)
		return;

	atcp_writeq(st, pad_buf, pad_len, NULL, NULL);
}

/*
 * Temporary Hack:
 *
 * TCP's Nagle algorithm and delayed-ack lead to poor performance when we send
 * two small messages back to back (i.e., header+data). The TCP_NODELAY option
 * is supposed to turn off Nagle, but it doesn't seem to work on Linux 2.4.
 * Because of this, if our data payload is small, we'll combine the header and
 * data, else send as two separate messages.
 */

int iscsi_writev(struct atcp_wr_state *st,
		 void *header, unsigned header_len,
		 const void *data, unsigned data_len)
{
	iscsi_trace(TRACE_NET_BUFF, __FILE__, __LINE__,
		    "NET: writing %u header bytes, %u data bytes\n",
		    header_len, data_len);

	atcp_writeq(st, header, header_len, hdr_cb_free, header);

	if (data && data_len > 0) {
		void *mem;

		mem = g_memdup(data, data_len);
		if (!mem)
			return -1;
		atcp_writeq(st, mem, data_len,
			   atcp_cb_free, mem);
	}

	send_padding(st, data_len);

	atcp_write_start(st);

	return header_len + data_len;
}

/*
 * Misc. Functions
 */

static const char HexString[] = "0123456789abcdef";

/* get the hex value (subscript) of the character */
static int HexStringIndex(const char *s, int c)
{
	const char     *cp;

	return (c == '0') ? 0 : ((cp = strchr(s, tolower(c))) ==
				 NULL) ? -1 : (int)(cp - s);
}

int
HexDataToText(uint8_t * data, uint32_t dataLength,
	      char *text, uint32_t textLength)
{
	uint32_t        n;

	if (!text || textLength == 0) {
		return -1;
	}
	if (!data || dataLength == 0) {
		*text = 0x0;
		return -1;
	}
	if (textLength < 3) {
		*text = 0x0;
		return -1;
	}
	*text++ = '0';
	*text++ = 'x';

	textLength -= 2;

	while (dataLength > 0) {

		if (textLength < 3) {
			*text = 0x0;
			return -1;
		}
		n = *data++;
		dataLength--;

		*text++ = HexString[(n >> 4) & 0xf];
		*text++ = HexString[n & 0xf];

		textLength -= 2;
	}

	*text = 0x0;

	return 0;
}

int
HexTextToData(const char *text, uint32_t textLength,
	      uint8_t * data, uint32_t dataLength)
{
	int             i;
	uint32_t        n1;
	uint32_t        n2;
	uint32_t        len = 0;

	if ((text[0] == '0') && (text[1] != 'x' || text[1] != 'X')) {
		/* skip prefix */
		text += 2;
		textLength -= 2;
	}
	if ((textLength % 2) == 1) {

		i = HexStringIndex(HexString, *text++);
		if (i < 0)
			return -1;	/* error, bad character */

		n2 = i;

		if (dataLength < 1) {
			return -1;	/* error, too much data */
		}
		*data++ = n2;
		len++;
	}
	while (*text != 0x0) {

		if ((i = HexStringIndex(HexString, *text++)) < 0) {
			/* error, bad character */
			return -1;
		}

		n1 = i;

		if (*text == 0x0) {
			/* error, odd string length */
			return -1;
		}

		if ((i = HexStringIndex(HexString, *text++)) < 0) {
			/* error, bad character */
			return -1;
		}

		n2 = i;

		if (len >= dataLength) {
			/* error, too much data */
			return len;
		}
		*data++ = (n1 << 4) | n2;
		len++;
	}

	return (len == 0) ? -1 : 0;
}

void GenRandomData(uint8_t * data, uint32_t length)
{
	unsigned        n;
	uint32_t        r;

	for (; length > 0; length--) {

		r = rand();
		r = r ^ (r >> 8);
		r = r ^ (r >> 4);
		n = r & 0x7;

		r = rand();
		r = r ^ (r >> 8);
		r = r ^ (r >> 5);
		n = (n << 3) | (r & 0x7);

		r = rand();
		r = r ^ (r >> 8);
		r = r ^ (r >> 5);
		n = (n << 2) | (r & 0x3);

		*data++ = n;
	}
}

void cdb2lba(uint32_t * lba, uint16_t * len, uint8_t * cdb)
{
	/* Some platforms (like strongarm) aligns on */
	/* word boundaries.  So htonl and ntohl won't */
	/* work here. */
	int             indian = 1;

	if (*(char *)(void *)&indian) {
		/* little endian */
		((uint8_t *) (void *)lba)[0] = cdb[5];
		((uint8_t *) (void *)lba)[1] = cdb[4];
		((uint8_t *) (void *)lba)[2] = cdb[3];
		((uint8_t *) (void *)lba)[3] = cdb[2];
		((uint8_t *) (void *)len)[0] = cdb[8];
		((uint8_t *) (void *)len)[1] = cdb[7];
	} else {
		((uint8_t *) (void *)lba)[0] = cdb[2];
		((uint8_t *) (void *)lba)[1] = cdb[3];
		((uint8_t *) (void *)lba)[2] = cdb[4];
		((uint8_t *) (void *)lba)[3] = cdb[5];
		((uint8_t *) (void *)len)[0] = cdb[7];
		((uint8_t *) (void *)len)[1] = cdb[8];
	}
}

void lba2cdb(uint8_t * cdb, uint32_t * lba, uint16_t * len)
{
	/* Some platforms (like strongarm) aligns on */
	/* word boundaries.  So htonl and ntohl won't */
	/* work here. */
	int             indian = 1;

	if (*(char *)(void *)&indian) {
		/* little endian */
		cdb[2] = ((uint8_t *) (void *)lba)[3];
		cdb[3] = ((uint8_t *) (void *)lba)[2];
		cdb[4] = ((uint8_t *) (void *)lba)[1];
		cdb[5] = ((uint8_t *) (void *)lba)[0];
		cdb[7] = ((uint8_t *) (void *)len)[1];
		cdb[8] = ((uint8_t *) (void *)len)[0];
	} else {
		/* big endian */
		cdb[2] = ((uint8_t *) (void *)lba)[2];
		cdb[3] = ((uint8_t *) (void *)lba)[3];
		cdb[4] = ((uint8_t *) (void *)lba)[0];
		cdb[5] = ((uint8_t *) (void *)lba)[1];
		cdb[7] = ((uint8_t *) (void *)len)[0];
		cdb[8] = ((uint8_t *) (void *)len)[1];
	}
}

enum {
	NETMASK_BUFFER_SIZE = 256
};

/* this struct is used to define a magic netmask value */
typedef struct magic_t {
	const char     *magic;	/* string to match */
	const char     *xform;	/* string to transform it into */
} magic_t;

static magic_t  magics[] = {
	{"any", "0/0"},
	{"all", "0/0"},
	{"none", "0/32"},
	{NULL, NULL},
};

/* return 1 if address is in netmask's range */
int allow_netmask(const char *netmaskarg, const char *addr)
{
	struct in_addr  a;
	struct in_addr  m;
	const char     *netmask;
	magic_t        *mp;
	char            maskaddr[NETMASK_BUFFER_SIZE];
	char           *cp;
	int             slash;
	int             i;

	/* firstly check for any magic values in the netmask */
	netmask = netmaskarg;
	for (mp = magics; mp->magic; mp++) {
		if (strcmp(netmask, mp->magic) == 0) {
			netmask = mp->xform;
			break;
		}
	}

	/* find out if slash notation has been used */
	memset(&a, 0x0, sizeof(a));
	if ((cp = strchr(netmask, '/')) == NULL) {
		strlcpy(maskaddr, netmask, sizeof(maskaddr));
		slash = 32;
	} else {
		strlcpy(maskaddr, netmask,
			MIN(sizeof(maskaddr), (int)(cp - netmask) + 1));
		slash = atoi(cp + 1);
	}

	/* if we have a wildcard "slash" netmask, then we allow it */
	if (slash == 0) {
		return 1;
	}

	/* canonicalise IPv4 address to dotted quad */
	for (i = 0, cp = maskaddr; *cp; cp++) {
		if (*cp == '.') {
			i += 1;
		}
	}
	for (; i < 3; i++)
		strcat(maskaddr, ".0");

	/* translate netmask to in_addr */
	if (!inet_aton(maskaddr, &m)) {
		fprintf(stderr,
			"allow_netmask: can't interpret mask `%s' as an IPv4 address\n",
			maskaddr);
		return 0;
	}

	/* translate address to in_addr */
	if (!inet_aton(addr, &a)) {
		fprintf(stderr,
			"allow_netmask: can't interpret address `%s' as an IPv4 address\n",
			addr);
		return 0;
	}
#ifdef ALLOW_NETMASK_DEBUG
	printf("addr %s %08x, mask %s %08x, slash %d\n", addr,
	       (htonl(a.s_addr) >> (32 - slash)), maskaddr,
	       (htonl(m.s_addr) >> (32 - slash)), slash);
#endif

	/* and return 1 if address is in netmask */
	return (htonl(a.s_addr) >> (32 - slash)) ==
	    (htonl(m.s_addr) >> (32 - slash));
}

#ifndef HAVE_STRLCPY
/*
 * Copy src to string dst of size siz.  At most siz-1 characters
 * will be copied.  Always NUL terminates (unless siz == 0).
 * Returns strlen(src); if retval >= siz, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t siz)
{
	char           *d = dst;
	const char     *s = src;
	size_t          n = siz;

	/* Copy as many bytes as will fit */
	if (n != 0 && --n != 0) {
		do {
			if ((*d++ = *s++) == 0)
				break;
		} while (--n != 0);
	}

	/* Not enough room in dst, add NUL and traverse rest of src */
	if (n == 0) {
		if (siz != 0)
			*d = '\0';	/* NUL-terminate dst */
		while (*s++) ;
	}

	return (s - src - 1);	/* count does not include NUL */
}
#endif

int fsetflags(const char *prefix, int fd, int or_flags)
{
	int flags, old_flags, rc;

	/* get current flags */
	old_flags = fcntl(fd, F_GETFL);
	if (old_flags < 0) {
		return -errno;
	}

	/* add or_flags */
	rc = 0;
	flags = old_flags | or_flags;

	/* set new flags */
	if (flags != old_flags)
		if (fcntl(fd, F_SETFL, flags) < 0) {
			rc = -errno;
		}

	return rc;
}

/*
 * CRC32C chksum,
 * as copied from Linux kernel's crypto/crc32c.c
 *
 *@Article{castagnoli-crc,
 * author =       { Guy Castagnoli and Stefan Braeuer and Martin Herrman},
 * title =        {{Optimization of Cyclic Redundancy-Check Codes with 24
 *                 and 32 Parity Bits}},
 * journal =      IEEE Transactions on Communication,
 * year =         {1993},
 * volume =       {41},
 * number =       {6},
 * pages =        {},
 * month =        {June},
 *}
 * Used by the iSCSI driver, possibly others, and derived from the
 * the iscsi-crc.c module of the linux-iscsi driver at
 * http://linux-iscsi.sourceforge.net.
 *
 * Following the example of lib/crc32, this function is intended to be
 * flexible and useful for all users.  Modules that currently have their
 * own crc32c, but hopefully may be able to use this one are:
 *  net/sctp (please add all your doco to here if you change to
 *            use this one!)
 *  <endoflist>
 *
 * Copyright (c) 2004 Cisco Systems, Inc.
 * Copyright (c) 2008 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 */

/*
 * This is the CRC-32C table
 * Generated with:
 * width = 32 bits
 * poly = 0x1EDC6F41
 * reflect input bytes = true
 * reflect output bytes = true
 */

static const uint32_t crc32c_table[256] = {
	0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
	0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
	0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
	0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
	0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
	0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
	0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
	0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
	0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
	0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
	0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
	0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
	0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
	0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
	0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
	0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
	0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
	0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
	0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
	0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
	0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
	0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
	0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
	0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
	0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
	0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
	0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
	0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
	0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
	0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
	0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
	0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
	0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
	0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
	0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
	0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
	0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
	0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
	0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
	0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
	0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
	0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
	0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
	0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
	0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
	0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
	0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
	0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
	0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
	0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
	0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
	0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
	0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
	0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
	0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
	0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
	0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
	0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
	0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
	0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
	0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
	0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
	0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
	0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

/*
 * Steps through buffer one byte at at time, calculates reflected
 * crc using table.
 */

uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length)
{
	while (length--)
		crc = crc32c_table[(crc ^ *data++) & 0xFFL] ^ (crc >> 8);

	return crc;
}

