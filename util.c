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

/*
 * Socket Functions
 */

int
modify_iov(struct iovec **iov_ptr, int *iovc, uint32_t offset, uint32_t length)
{
	int             len;
	int             disp = offset;
	int             i;
	struct iovec   *iov = *iov_ptr;
	char           *basep;

	/* Given <offset>, find beginning iovec and modify its base and length */
	len = 0;
	for (i = 0; i < *iovc; i++) {
		len += iov[i].iov_len;
		if (len > offset) {
			iscsi_trace(TRACE_NET_IOV, __FILE__, __LINE__,
				    "found offset %u in iov[%d]\n", offset, i);
			break;
		}
		disp -= iov[i].iov_len;
	}
	if (i == *iovc) {
		iscsi_trace_error(__FILE__, __LINE__,
				  "sum of iov lens (%u) < offset (%u)\n", len,
				  offset);
		return -1;
	}
	iov[i].iov_len -= disp;
	basep = iov[i].iov_base;
	basep += disp;
	iov[i].iov_base = basep;
	*iovc -= i;
	*iov_ptr = &(iov[i]);
	iov = *iov_ptr;

	/*
	 * Given <length>, find ending iovec and modify its length (base does
	 * not change)
	 */

	len = 0;		/* we should re-use len and i here... */
	for (i = 0; i < *iovc; i++) {
		len += iov[i].iov_len;
		if (len >= length) {
			iscsi_trace(TRACE_NET_IOV, __FILE__, __LINE__,
				    "length %u ends in iovec[%d]\n", length, i);
			break;
		}
	}
	if (i == *iovc) {
		iscsi_trace_error(__FILE__, __LINE__,
				  "sum of iovec lens (%u) < length (%u)\n", len,
				  length);
		for (i = 0; i < *iovc; i++) {
			iscsi_trace_error(__FILE__, __LINE__,
					  "iov[%d].iov_base = %p (len %u)\n", i,
					  iov[i].iov_base,
					  (unsigned)iov[i].iov_len);
		}
		return -1;
	}
	iov[i].iov_len -= (len - length);
	*iovc = i + 1;

	iscsi_trace(TRACE_NET_IOV, __FILE__, __LINE__, "new iov:\n");
	len = 0;
	for (i = 0; i < *iovc; i++) {
		iscsi_trace(TRACE_NET_IOV, __FILE__, __LINE__,
			    "iov[%d].iov_base = %p (len %u)\n", i,
			    iov[i].iov_base, (unsigned)iov[i].iov_len);
		len += iov[i].iov_len;
	}
	iscsi_trace(TRACE_NET_IOV, __FILE__, __LINE__,
		    "new iov length: %u bytes\n", len);

	return 0;
}

#ifndef MAXSOCK
#define MAXSOCK	16
#endif

void send_padding(GConn *conn, unsigned int len_out)
{
	int i, pad_len;
	char pad_buf[4] = { 0, 0, 0, 0 };

	i = len_out & 0x3;
	if (!i)
		return;
	
	pad_len = 4 - i;
	gnet_conn_write(conn, pad_buf, pad_len);
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

int
iscsi_sock_send_header_and_data(GConn * conn,
				const void *header, unsigned header_len,
				const void *data, unsigned data_len, int iovc)
{
	iscsi_trace(TRACE_NET_BUFF, __FILE__, __LINE__,
		    "NET: writing %u header bytes\n", header_len);
	gnet_conn_write(conn, (void *)header, header_len);

	if (!iovc) {
		iscsi_trace(TRACE_NET_BUFF, __FILE__, __LINE__,
			    "NET: writing %u data bytes\n", data_len);
		if (data_len > 0)
			gnet_conn_write(conn, (void *)data, data_len);

	} else {
		struct iovec    iov[ISCSI_MAX_IOVECS];
		int             i;

		memcpy(&iov[0], data, sizeof(struct iovec) * iovc);

		data_len = 0;

		for (i = 0; i < iovc; i++) {
			iscsi_trace(TRACE_NET_BUFF, __FILE__, __LINE__,
				    "NET: writing %u bytes (iov %d)\n",
				    data_len, i);
			if (iov[i].iov_len > 0)
				gnet_conn_write(conn, iov[i].iov_base,
						iov[i].iov_len);

			data_len += iov[i].iov_len;
		}
	}

	send_padding(conn, data_len);

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
