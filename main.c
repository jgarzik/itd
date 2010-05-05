
/*
 * Copyright 2008 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include "itd-config.h"

#include <sys/socket.h>
#include <netdb.h>
#include <glib.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <argp.h>
#include <event.h>
#include <net/if.h>
#include <ifaddrs.h>

#include "iscsi.h"
#include "target.h"
#include "parameters.h"
#include "scsi_cmd_codes.h"

uint32_t iscsi_debug_level = 0;

static bool server_running = true;
static bool opt_strict_free = false;
void *data_mem = NULL;
uint32_t data_mem_lba;

enum {
	data_lba_size	= 512,
};

static struct globals gbls = {
	.port		= 3260,
};

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "trace", 'T', "TRACE-LIST", 0,
	  "Comma-separate list of one or more of: net, iscsi, scsi, osd, all" },
	{ "port", 'p', "PORT", 0,
	  "Bind to TCP port PORT.  Default: 3290 (iSCSI IANA registered port)" },
	{ "strict-free", 1001, NULL, 0,
	  "For memory-checker runs.  When shutting down server, free local "
	  "heap, rather than simply exit(2)ing and letting OS clean up." },

	{ }
};

static const char doc[] =
PACKAGE_NAME " - iSCSI target daemon";

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, NULL, doc };

static const uint8_t def_rw_recovery_mpage[RW_RECOVERY_MPAGE_LEN] = {
	RW_RECOVERY_MPAGE,
	RW_RECOVERY_MPAGE_LEN - 2,
	(1 << 7) | (1 << 6),	/* AWRE, ARRE */
	0,			/* read retry count */
	0, 0, 0, 0,
	0,			/* write retry count */
	0, 0, 0
};

static const uint8_t def_cache_mpage[CACHE_MPAGE_LEN] = {
	CACHE_MPAGE,
	CACHE_MPAGE_LEN - 2,
	(1 << 0),	/* RCD=1 */
	0, 0, 0, 0, 0, 0, 0, 0, 0,
	(1 << 5),	/* DRA=1 */
	0, 0, 0, 0, 0, 0, 0
};

static const uint8_t def_control_mpage[CONTROL_MPAGE_LEN] = {
	CONTROL_MPAGE,
	CONTROL_MPAGE_LEN - 2,
	2,	/* DSENSE=0, GLTSD=1 */
	0,	/* [QAM+QERR may be 1, see 05-359r1] */
	0, 0, 0, 0, 0xff, 0xff,
	0, 30	/* extended self test time, see 05-359r1 */
};

static const uint8_t def_fmt_dev_mpage[FMT_DEV_MPAGE_LEN] = {
	FMT_DEV_MPAGE,
	FMT_DEV_MPAGE_LEN - 2,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	data_lba_size >> 8, data_lba_size & 0xff,
	0, 0, 0, 0, 0, 0,
	(1 << 6),	/* HSEC=1 */
	0, 0, 0
};

static const uint8_t def_medium_types_mpage[MEDIUM_TYPES_MPAGE_LEN] = {
	MEDIUM_TYPES_MPAGE,
	MEDIUM_TYPES_MPAGE_LEN - 2,
	0, 0, 0, 0, 0, 0
};

static uint16_t scsi_d16(const uint8_t *buf)
{
	return	(((uint16_t) buf[0]) << 8) |
		(((uint16_t) buf[1]));
}

static uint32_t scsi_d32(const uint8_t *buf)
{
	return	(((uint32_t) buf[0]) << 24) |
		(((uint32_t) buf[1]) << 16) |
		(((uint32_t) buf[2]) << 8) |
		(((uint32_t) buf[3]));
}

static void scsi_6_lba_len(const uint8_t *cdb, uint64_t *plba, uint32_t *plen)
{
	uint64_t lba = 0;
	uint32_t len;

	lba |= ((uint64_t)(cdb[1] & 0x1f)) << 16;
	lba |= ((uint64_t)cdb[2]) << 8;
	lba |= ((uint64_t)cdb[3]);

	len = cdb[4];

	*plba = lba;
	*plen = len;
}

static void scsi_10_lba_len(const uint8_t *cdb, uint64_t *plba, uint32_t *plen)
{
	uint64_t lba = 0;
	uint32_t len = 0;

	lba |= ((uint64_t)cdb[2]) << 24;
	lba |= ((uint64_t)cdb[3]) << 16;
	lba |= ((uint64_t)cdb[4]) << 8;
	lba |= ((uint64_t)cdb[5]);

	len |= ((uint32_t)cdb[7]) << 8;
	len |= ((uint32_t)cdb[8]);

	*plba = lba;
	*plen = len;
}

static void scsi_16_lba_len(const uint8_t *cdb, uint64_t *plba, uint32_t *plen)
{
	uint64_t lba = 0;
	uint32_t len = 0;

	lba |= ((uint64_t)cdb[2]) << 56;
	lba |= ((uint64_t)cdb[3]) << 48;
	lba |= ((uint64_t)cdb[4]) << 40;
	lba |= ((uint64_t)cdb[5]) << 32;
	lba |= ((uint64_t)cdb[6]) << 24;
	lba |= ((uint64_t)cdb[7]) << 16;
	lba |= ((uint64_t)cdb[8]) << 8;
	lba |= ((uint64_t)cdb[9]);

	len |= ((uint32_t)cdb[10]) << 24;
	len |= ((uint32_t)cdb[11]) << 16;
	len |= ((uint32_t)cdb[12]) << 8;
	len |= ((uint32_t)cdb[13]);

	*plba = lba;
	*plen = len;
}

static int sense_fill(bool desc, uint8_t *buf, uint8_t key,
		      uint8_t asc, uint8_t ascq)
{
	uint16_t *buf16 = (uint16_t *) buf;

	/* iSCSI sense length; hardcoded at 14 right now */
	*buf16 = htons(14);
	buf += 2;

	if (desc) {
		buf[0] = 0x72;	/* descriptor, current */
		buf[1] = key;
		buf[2] = asc;
		buf[3] = ascq;
		buf[7] = 0;
	} else {
		buf[0] = 0x70;	/* fixed, current */
		buf[2] = key;
		buf[7] = 0xa;
		buf[12] = asc;
		buf[13] = ascq;
	}

	return 2 + 14;	/* number of bytes in buffer used */
}

static int sense_inval_field(bool desc, uint8_t *buf)
{
	/* illegal request - invalid field in CDB */
	return sense_fill(desc, buf, SKEY_ILLEGAL_REQUEST, 0x24, 0x0);
}

static void scsierr_inval(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *buf)
{
	/* invalid field in CDB */
	scsi_cmd->status = SCSI_CHECK_CONDITION;
	scsi_cmd->length = sense_inval_field(false, buf);
}

static void scsierr_opcode(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *buf)
{
	/* unknown SCSI opcode */
	scsi_cmd->status = SCSI_CHECK_CONDITION;
	scsi_cmd->length = sense_fill(false, buf, SKEY_ILLEGAL_REQUEST, 0x20, 0x0);
}

static int device_id;

int device_init(struct globals *a, targv_t * b, struct disc_target *c)
{
	return ++device_id;
}

static void scsiop_inquiry_std(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *rbuf)
{
	const uint8_t versions[] = {
		0x60,   /* SAM-3 (no version claimed) */

		0x03,
		0x20,   /* SBC-2 (no version claimed) */

		0x02,
		0x60    /* SPC-3 (no version claimed) */
	};
	const uint8_t hdr[] = {
		TYPE_DISK,
		0,
		0x5,    /* claim SPC-3 version compatibility */
		2,
		95 - 4
	};

	memcpy(rbuf, hdr, sizeof(hdr));

	memset(&rbuf[8], ' ', 8 + 16 + 4);

	memcpy(&rbuf[8], ISCSI_VENDOR, strlen(ISCSI_VENDOR));	/* vendor */
	memcpy(&rbuf[16], ISCSI_PRODUCT, strlen(ISCSI_PRODUCT));/* product */
	memcpy(&rbuf[32], ISCSI_FWREV, strlen(ISCSI_FWREV));	/* fw rev */

        memcpy(rbuf + 59, versions, sizeof(versions));

	scsi_cmd->length = 95;
	scsi_cmd->input = 1;
}

static void scsiop_inquiry_list(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *rbuf)
{
	const uint8_t pages[] = {
		0x00,   /* page 0x00, list of pages (this page) */
		0x83,   /* page 0x83, device ident page */
	};

	rbuf[3] = sizeof(pages);	/* number of supported VPD pages */
	memcpy(rbuf + 4, pages, sizeof(pages));

	scsi_cmd->length = 4 + sizeof(pages);
	scsi_cmd->input = 1;
}

static void scsiop_inquiry_devid(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *buf)
{
	uint16_t *page_len = (uint16_t *) (buf + 2);
	uint16_t i = 4;
	char s[64];

	buf[0] = TYPE_DISK;
	buf[1] = 0x83;		/* our page code */

	sprintf(s, "%s %s", ISCSI_PRODUCT, ISCSI_FWREV);

	/* !PIV, LUN assoc., ASCII identifier, type=vendor-specific */
	buf[i + 0] = INQUIRY_DEVICE_CODESET_UTF8;
	buf[i + 3] = strlen(s);
	memcpy(&buf[i + 4], s, strlen(s));

	i += (4 + strlen(s));

	*page_len = htons(i - 4);

	scsi_cmd->length = i;
	scsi_cmd->input = 1;
}

static unsigned int msense_ctl_mode(uint8_t *buf)
{
	memcpy(buf, def_control_mpage, sizeof(def_control_mpage));
	return sizeof(def_control_mpage);
}

static unsigned int msense_cache(uint8_t *buf)
{
	memcpy(buf, def_cache_mpage, sizeof(def_cache_mpage));
	return sizeof(def_cache_mpage);
}

static unsigned int msense_fmt_dev(uint8_t *buf)
{
	memcpy(buf, def_fmt_dev_mpage, sizeof(def_fmt_dev_mpage));
	return sizeof(def_fmt_dev_mpage);
}

static unsigned int msense_rw_recovery(uint8_t *buf)
{
	memcpy(buf, def_rw_recovery_mpage, sizeof(def_rw_recovery_mpage));
	return sizeof(def_rw_recovery_mpage);
}

static unsigned int msense_medium_types(uint8_t *buf)
{
	memcpy(buf, def_medium_types_mpage, sizeof(def_medium_types_mpage));
	return sizeof(def_medium_types_mpage);
}

static void scsiop_mode_sense(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *rbuf,
			      bool six_byte)
{
	const uint8_t *scsicmd = scsi_cmd->cdb;
	uint8_t *p = rbuf;
	const uint8_t blk_desc[] = {
		0, 0, 0, 0,	/* number of blocks */
		0,		/* density code */
		0, 0x2, 0x0	/* block length: 512 bytes */
	};
	uint8_t pg, spg;
	unsigned int ebd, page_control;
	uint8_t dpofua;

	ebd = !(scsicmd[1] & 0x8);      /* dbd bit inverted == edb */
	/*
	 * LLBA bit in msense(10) ignored (compliant)
	 */

	page_control = scsicmd[2] >> 6;
	switch (page_control) {
	case 0: /* current */
		break;  /* supported */
	case 3: /* saved */
		goto saving_not_supp;
	case 1: /* changeable */
	case 2: /* defaults */
	default:
		goto invalid_fld;
	}

	if (six_byte)
		p += 4 + (ebd ? 8 : 0);
	else
		p += 8 + (ebd ? 8 : 0);

	pg = scsicmd[2] & 0x3f;
	spg = scsicmd[3];
	/*
	 * No mode subpages supported (yet) but asking for _all_
	 * subpages may be valid
	 */
	if (spg && (spg != ALL_SUB_MPAGES))
		goto invalid_fld;

	switch(pg) {
	case RW_RECOVERY_MPAGE:
		p += msense_rw_recovery(p);
		break;

	case FMT_DEV_MPAGE:
		p += msense_fmt_dev(p);
		break;

	case CACHE_MPAGE:
		p += msense_cache(p);
		break;

	case CONTROL_MPAGE:
		p += msense_ctl_mode(p);
		break;

	case MEDIUM_TYPES_MPAGE:
		p += msense_medium_types(p);
		break;

	case ALL_MPAGES:
		p += msense_rw_recovery(p);
		p += msense_fmt_dev(p);
		p += msense_cache(p);
		p += msense_ctl_mode(p);
		p += msense_medium_types(p);
		break;

	default:		/* invalid page code */
		goto invalid_fld;
	}

	dpofua = 0;

	if (six_byte) {
		rbuf[0] = p - rbuf - 1;
		rbuf[2] |= dpofua;
		if (ebd) {
			rbuf[3] = sizeof(blk_desc);
			memcpy(rbuf + 4, blk_desc, sizeof(blk_desc));
		}
	} else {
		unsigned int output_len = p - rbuf - 2;

		rbuf[0] = output_len >> 8;
		rbuf[1] = output_len;
		rbuf[3] |= dpofua;
		if (ebd) {
			rbuf[7] = sizeof(blk_desc);
			memcpy(rbuf + 8, blk_desc, sizeof(blk_desc));
		}
	}

	scsi_cmd->length = p - rbuf;
	scsi_cmd->input = 1;
	return;

invalid_fld:
	scsierr_inval(scsi_cmd, rbuf);
	return;

saving_not_supp:
	 /* "Saving parameters not supported" */
	scsi_cmd->status = SCSI_CHECK_CONDITION;
	scsi_cmd->length = sense_fill(false, rbuf, SKEY_ILLEGAL_REQUEST, 0x39, 0x0);
	return;
}

static void scsiop_read_cap(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *buf,
			    bool short_form)
{
	uint32_t *buf32 = (uint32_t *) buf;

	if (short_form) {
		buf32[0] = htonl(data_mem_lba - 1);
		buf32[1] = htonl(data_lba_size);

		scsi_cmd->length = 4 * 2;
	} else {
		*((uint64_t *)buf) = GUINT64_TO_BE((uint64_t)data_mem_lba - 1);
		buf32[2] = htonl(data_lba_size);

		scsi_cmd->length = 4 * 3;
	}

	scsi_cmd->input = 1;
}

static void scsiop_report_luns(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *buf)
{
	uint32_t *buf32 = (uint32_t *) buf;

	*buf32 = htonl(1 * 8);		/* one LUN, whose value is zero */

	scsi_cmd->length = 8 + (1 * 8);
	scsi_cmd->input = 1;
}

static void scsiop_supported_tmf(struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *buf)
{
	const uint8_t *cdb = scsi_cmd->cdb;
	uint32_t alloc_len;

	alloc_len = scsi_d32(cdb + 6);
	if (alloc_len < 4)
		goto err_out;

	/* we support no TMFs at present; leave data zeroed */

	scsi_cmd->length = 4;
	scsi_cmd->input = 1;

	return;

err_out:
	scsierr_inval(scsi_cmd, buf);
}

static void scsiop_data_xfer(struct target_session *sess,
			     struct target_cmd *tc,
			     struct iscsi_scsi_cmd_args *scsi_cmd, uint8_t *buf,
			     bool is_write, int byte_size)
{
	const uint8_t *cdb = scsi_cmd->cdb;
	uint64_t lba = 0;
	uint32_t len = 0;
	void *mem;

	switch (byte_size) {
	case 6:		scsi_6_lba_len(cdb, &lba, &len); break;
	case 10:	scsi_10_lba_len(cdb, &lba, &len); break;
	case 16:	scsi_16_lba_len(cdb, &lba, &len); break;
	}

	if ((len > data_mem_lba) ||
	    ((lba + len) > data_mem_lba) ||
	    ((lba + len) < lba))
		goto err_out;

	mem = data_mem + (lba * data_lba_size);

	if (is_write) {
		if (target_transfer_data(sess, scsi_cmd) < 0)
			goto err_out;	/* FIXME: improve err-case sense */
		if (!sess->want_data_pdu && (device_commit(sess, tc) < 0))
			goto err_out;	/* FIXME: improve err-case sense */
	} else {
		scsi_cmd->input = 1;
		scsi_cmd->send_data = mem;
	}

	return;

err_out:
	scsierr_inval(scsi_cmd, buf);
}

int device_commit(struct target_session *sess, struct target_cmd *tc)
{
	/* FIXME: handle committed WRITE data */
	return 0;
}

int device_command(struct target_session *sess, struct target_cmd *tc)
{
	struct iscsi_scsi_cmd_args *scsi_cmd = tc->scsi_cmd;
	const uint8_t *cdb = scsi_cmd->cdb;
	uint8_t *buf;
	bool is_write;

	switch (cdb[0]) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_16:
		is_write = true;
		break;

	default:
		is_write = false;
		break;
	}

	scsi_cmd->status = SCSI_SUCCESS;

	if (!is_write)
		scsi_cmd->length = 0;

	scsi_cmd->send_data = buf = sess->outbuf;

	memset(buf, 0, sizeof(sess->outbuf));

	switch (cdb[0]) {
	case FORMAT_UNIT:
		/* format, iff FMTDATA, CMPLST and defect list format == 0 */
		if ((cdb[1] & 0x1f) == 0)
			memset(data_mem, 0, data_mem_lba * data_lba_size);
		else
			scsierr_inval(scsi_cmd, buf);
		break;

	case INQUIRY:
		if (cdb[1] & (1 << 1))			/* CmdDt set? */
			scsierr_inval(scsi_cmd, buf);

		else if (!(cdb[1] & (1 << 0)))		/* EVPD clear? */
			scsiop_inquiry_std(scsi_cmd, buf);

		else
			switch (cdb[2]) {		/* EVPD page */
			case 0x00:	scsiop_inquiry_list(scsi_cmd, buf); break;
			case 0x83:	scsiop_inquiry_devid(scsi_cmd, buf); break;
			default:	scsierr_inval(scsi_cmd, buf); break;
			}
		break;

	case MAINTENANCE_IN:
		switch (cdb[1] & 0x1f) {	/* service action */
		case SAI_SUPPORTED_TMF:
			scsiop_supported_tmf(scsi_cmd, buf);
			break;

		default:
			scsierr_opcode(scsi_cmd, buf);
			break;
		}
		break;

	case MODE_SELECT_6:
	case MODE_SELECT_10:
		/* unconditionally return invalid-field-in-CDB */
		scsierr_inval(scsi_cmd, buf);
		break;

	case MODE_SENSE:
		scsiop_mode_sense(scsi_cmd, buf, true);
		break;

	case MODE_SENSE_10:
		scsiop_mode_sense(scsi_cmd, buf, false);
		break;

	case READ_CAPACITY:
		scsiop_read_cap(scsi_cmd, buf, true);
		break;

	case REPORT_LUNS:
		scsiop_report_luns(scsi_cmd, buf);
		break;

	case REQUEST_SENSE:
		scsi_cmd->length = sense_fill(cdb[1] & (1 << 0), buf, 0, 0, 0);
		scsi_cmd->input = 1;
		break;

	case SEEK_10:
		/* provided a valid range, seek is a no-op */
		if (scsi_d32(cdb + 2) >= data_mem_lba)
			scsierr_inval(scsi_cmd, buf);
		break;

	case SEND_DIAGNOSTIC:
		/* default test immediately succeeds. all others invalid. */
		if (scsi_d16(cdb + 3) || !(cdb[1] & (1 << 2)))
			scsierr_inval(scsi_cmd, buf);
		break;

	case SERVICE_ACTION_IN:
		switch (cdb[1] & 0x1f) {	/* service action */
		case SAI_READ_CAPACITY_16:
			scsiop_read_cap(scsi_cmd, buf, false);
			break;

		default:
			scsierr_opcode(scsi_cmd, buf);
			break;
		}
		break;

	case READ_6:
		scsiop_data_xfer(sess, tc, scsi_cmd, buf, false, 6);
		break;

	case READ_10:
		scsiop_data_xfer(sess, tc, scsi_cmd, buf, false, 10);
		break;

	case READ_16:
		scsiop_data_xfer(sess, tc, scsi_cmd, buf, false, 16);
		break;

	case WRITE_6:
		scsiop_data_xfer(sess, tc, scsi_cmd, buf, true, 6);
		break;

	case WRITE_10:
		scsiop_data_xfer(sess, tc, scsi_cmd, buf, true, 10);
		break;

	case WRITE_16:
		scsiop_data_xfer(sess, tc, scsi_cmd, buf, true, 16);
		break;

	case PREFETCH_10:
	case PREFETCH_16:
	case SYNC_CACHE:
	case SYNC_CACHE_16:
	case TEST_UNIT_READY:
		/* do nothing - success */
		break;

	default:
		scsierr_opcode(scsi_cmd, buf);
		break;
	}

	return 0;
}

int device_shutdown(struct target_session *f, bool strict_free)
{
	return 0;
}

static void tcp_srv_event(int fd, short events, void *userdata)
{
	struct server_socket *sock = userdata;

	target_accept(&gbls, sock);
}

static void applogerr(const char *msg)
{
	perror(msg);
}

#define applog(lvl, fmt, ...)					\
	iscsi_trace(TRACE_NET_DEBUG, __FILE__, __LINE__,	\
		    fmt, ## __VA_ARGS__)

static bool find_local_addr_str(char *str, size_t str_size)
{
	struct ifaddrs *ifa = NULL, *tmp, *cur;
	bool loopback = false;
	bool rcb = false;

	if (getifaddrs(&ifa) < 0)
		return false;

restart:
	tmp = ifa;
	while (tmp) {
		cur = tmp;
		tmp = tmp->ifa_next;

		if (!(cur->ifa_flags & IFF_UP))
			continue;
		if (!loopback && (cur->ifa_flags & IFF_LOOPBACK))
			continue;
		if (cur->ifa_addr->sa_family != AF_INET &&
		    cur->ifa_addr->sa_family != AF_INET6)
			continue;
		if (cur->ifa_addr->sa_family == AF_INET6) {
			struct sockaddr_in6 *a6 =
				(struct sockaddr_in6 *) cur->ifa_addr;

			if (!loopback && IN6_IS_ADDR_LOOPBACK(&a6->sin6_addr))
				continue;
			if (IN6_IS_ADDR_UNSPECIFIED(&a6->sin6_addr) ||
			    IN6_IS_ADDR_LINKLOCAL(&a6->sin6_addr))
				continue;
		}

		/* passed exclusionary checks; this will be our
		 * auto-detected target address, for the case when
		 * we bind to any-address
		 */
		getnameinfo(cur->ifa_addr, sizeof(struct sockaddr),
			    str, str_size, NULL, 0,
			    NI_NUMERICHOST | NI_NUMERICSERV);
		str[str_size - 1] = 0;
		rcb = true;
		goto done;
	}

	if (!loopback) {
		loopback = true;
		goto restart;
	}

done:
	freeifaddrs(ifa);

	return rcb;
}

static int net_open_socket(int addr_fam, int sock_type, int sock_prot,
			   int addr_len, void *addr_ptr)
{
	struct server_socket *sock;
	int fd, on;
	int rc;

	fd = socket(addr_fam, sock_type, sock_prot);
	if (fd < 0) {
		rc = errno;
		applogerr("tcp socket");
		return -rc;
	}

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
		rc = errno;
		applogerr("setsockopt(SO_REUSEADDR)");
		close(fd);
		return -rc;
	}

	if (bind(fd, addr_ptr, addr_len) < 0) {
		rc = errno;
		applogerr("tcp bind");
		close(fd);
		return -rc;
	}

	if (listen(fd, 100) < 0) {
		rc = errno;
		applogerr("tcp listen");
		close(fd);
		return -rc;
	}

	rc = fsetflags("tcp server", fd, O_NONBLOCK);
	if (rc) {
		close(fd);
		return rc;
	}

	sock = calloc(1, sizeof(*sock));
	if (!sock) {
		close(fd);
		return -ENOMEM;
	}

	sock->fd = fd;

	sock->addrlen = addr_len;
	memcpy(&sock->addr, addr_ptr, addr_len);

	if (!find_local_addr_str(sock->addr_str, sizeof(sock->addr_str))) {
		getnameinfo(addr_ptr, addr_len,
			    sock->addr_str, sizeof(sock->addr_str), NULL, 0,
			    NI_NUMERICHOST | NI_NUMERICSERV);
		sock->addr_str[sizeof(sock->addr_str) - 1] = 0;
	}

	snprintf(gbls.host, sizeof(gbls.host), "%s", sock->addr_str);
	snprintf(gbls.targetaddress, sizeof(gbls.targetaddress), "%s:%u,1",
		 gbls.host, gbls.port);

	event_set(&sock->ev, fd, EV_READ | EV_PERSIST, tcp_srv_event, sock);

	if (event_add(&sock->ev, NULL)) {
		close(fd);
		free(sock);
		return -EIO;
	}

	gbls.sockets = g_list_append(gbls.sockets, sock);
	return fd;
}

static int net_open_known(int port_num)
{
	int ipv6_found;
	int rc;
	struct addrinfo hints, *res, *res0;
	char portstr[32];

	snprintf(portstr, sizeof(portstr), "%d", port_num);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	rc = getaddrinfo(NULL, portstr, &hints, &res0);
	if (rc) {
		applog(LOG_ERR, "getaddrinfo(*:%s) failed: %s",
		       portstr, gai_strerror(rc));
		rc = -EINVAL;
		goto err_addr;
	}

	/*
	 * We rely on getaddrinfo to discover if the box supports IPv6.
	 * Much easier to sanitize its output than to try to figure what
	 * to put into ai_family.
	 *
	 * These acrobatics are required on Linux because we should bind
	 * to ::0 if we want to listen to both ::0 and 0.0.0.0. Else, we
	 * may bind to 0.0.0.0 by accident (depending on order getaddrinfo
	 * returns them), then bind(::0) fails and we only listen to IPv4.
	 */
	ipv6_found = 0;
	for (res = res0; res; res = res->ai_next) {
		if (res->ai_family == PF_INET6)
			ipv6_found = 1;
	}

	for (res = res0; res; res = res->ai_next) {
		char listen_host[65], listen_serv[65];

		if (ipv6_found && res->ai_family == PF_INET)
			continue;

		rc = net_open_socket(res->ai_family, res->ai_socktype,
				     res->ai_protocol,
				     res->ai_addrlen, res->ai_addr);
		if (rc < 0)
			goto err_out;
		getnameinfo(res->ai_addr, res->ai_addrlen,
			    listen_host, sizeof(listen_host),
			    listen_serv, sizeof(listen_serv),
			    NI_NUMERICHOST | NI_NUMERICSERV);

		applog(LOG_INFO, "Listening on %s port %s\n",
		       listen_host, listen_serv);
	}

	freeaddrinfo(res0);
	return 0;

err_out:
	freeaddrinfo(res0);
err_addr:
	return rc;
}

static int net_init(void)
{
	int rc;

	rc = net_open_known(gbls.port);
	if (rc)
		return rc;

	return 0;
}

static targv_t tv;

static int master_iscsi_init(void)
{
	targv_t *tvp = &tv;
	char tgt[256] = "iqn.2010-04.us.yyz.bd.itd";
	char iqn[256] = "iqn.2010-04.us.yyz.bd.itd:target0";

	memset(&tv, 0, sizeof(tv));

	ALLOC(struct disc_target, tvp->v, tvp->size, tvp->c, 14, 14,
	      "master_iscsi_init", exit(EXIT_FAILURE));

	tvp->v[tvp->c].de.type = DE_DEVICE;
	tvp->v[tvp->c].de.u.dp = NULL;
	tvp->v[tvp->c].target = strdup(tgt);
	tvp->v[tvp->c].iqn = strdup(iqn);
	tvp->v[tvp->c].mask = strdup("0/0");
	tvp->c += 1;

	return target_init(&gbls, tvp, tgt);
}

static void master_iscsi_exit(void)
{
	target_shutdown(&gbls, opt_strict_free);
}

static int mem_init(void)
{
	data_mem_lba = (100 * 1024 * 1024) / data_lba_size;

	data_mem = calloc(1, data_mem_lba * data_lba_size);
	if (!data_mem)
		return -1;

	return 0;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	int v;
	char *initial_str, *s;

	switch(key) {
	case 'T':
		initial_str = arg;
		while ((s = strtok(initial_str, ", ")) != NULL) {
			set_debug(s);
			initial_str = NULL;
		}
		fprintf(stderr, "New iSCSI tracing level: 0x%x\n",
			iscsi_debug_level);
		break;

	case 'p':
		/*
		 * We do not permit "0" as an argument in order to be safer
		 * against a malfunctioning jumpstart script or a simple
		 * misunderstanding by a human operator.
		 */
		v = atoi(arg);
		if (v > 0 && v < 65536) {
			gbls.port = v;
		} else {
			fprintf(stderr, "invalid port: '%s'\n", arg);
			argp_usage(state);
		}
		break;
	case 1001:
		opt_strict_free = true;
		break;

	case ARGP_KEY_ARG:
		argp_usage(state);	/* too many args */
		break;
	case ARGP_KEY_END:
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void term_signal(int signo)
{
	server_running = false;
	event_loopbreak();
}

int main(int argc, char *argv[])
{
	error_t aprc;

	event_init();

	/*
	 * parse command line
	 */

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	/* properly capture TERM and other signals */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);

	if (mem_init())
		return 1;
	if (net_init())
		return 1;
	if (master_iscsi_init())
		return 1;

	while (server_running)
		event_dispatch();

	master_iscsi_exit();

	return 0;
}
