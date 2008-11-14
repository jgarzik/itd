
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

#include <glib.h>
#include <gnet.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#include "iscsi.h"
#include "target.h"
#include "parameters.h"
#include "scsi_cmd_codes.h"

uint32_t        iscsi_debug_level = 0;

static GServer *tcp_srv;

static struct globals gbls = {
	.port = 3260,
};

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
	return sense_fill(desc, buf, SKEY_ILLEGAL_REQUEST, 0x24, 0x0);
}

int device_init(struct globals *a, targv_t * b, struct disc_target *c)
{
	return -1;
}

static void scsiop_inquiry_std(struct iscsi_scsi_cmd_args *args, uint8_t *rbuf)
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

	args->length = 95;
	args->input = 1;
}

static void scsiop_inquiry_list(struct iscsi_scsi_cmd_args *args, uint8_t *rbuf)
{
	const uint8_t pages[] = {
		0x00,   /* page 0x00, this page */
		0x83,   /* page 0x83, device ident page */
	};

	rbuf[3] = sizeof(pages);	/* number of supported VPD pages */
	memcpy(rbuf + 4, pages, sizeof(pages));

	args->length = 4 + sizeof(pages);
	args->input = 1;
}

static void scsiop_inquiry_devid(struct iscsi_scsi_cmd_args *args, uint8_t *buf)
{
	uint16_t *page_len = (uint16_t *) (buf + 2);
	uint16_t i = 4;
	char s[64];

	buf[0] = TYPE_DISK;
	buf[1] = 0x83;

	sprintf(s, "%s %s", ISCSI_PRODUCT, ISCSI_FWREV);

	buf[i + 0] = INQUIRY_DEVICE_CODESET_UTF8;
	buf[i + 3] = strlen(s);
	memcpy(&buf[i + 4], s, strlen(s));

	i += (4 + strlen(s));

	*page_len = htons(i - 4);

	args->length = i;
	args->input = 1;
}

static void scsiop_report_luns(struct iscsi_scsi_cmd_args *args, uint8_t *buf)
{
	uint32_t *buf32 = (uint32_t *) buf;

	*buf32 = htonl(1 * 8);		/* one LUN, whose value is zero */

	args->length = 8 + (1 * 8);
	args->input = 1;
}

int device_command(struct target_session *sess, struct target_cmd *tc)
{
	struct iscsi_scsi_cmd_args *args = tc->scsi_cmd;
	uint8_t *buf, *cdb = args->cdb;
	int rc = 0;

	args->status = SCSI_SUCCESS;
	args->length = 0;
	args->send_data = buf = sess->outbuf;

	memset(buf, 0, sizeof(sess->outbuf));

	switch (cdb[0]) {
	case INQUIRY:
		if (!(cdb[1] & (1 << 0)))
			scsiop_inquiry_std(args, buf);
		else if (cdb[2] == 0x00)
			scsiop_inquiry_list(args, buf);
		else if (cdb[2] == 0x83)
			scsiop_inquiry_devid(args, buf);
		else {
			args->status = SCSI_CHECK_CONDITION;
			args->length = sense_inval_field(false, buf);
		}
		break;

	case REPORT_LUNS:
		scsiop_report_luns(args, buf);
		break;

	case TEST_UNIT_READY:
		/* do nothing - success */
		break;

	default:
		/* unknown SCSI opcode */
		args->status = SCSI_CHECK_CONDITION;
		args->length =
			sense_fill(false, buf, SKEY_ILLEGAL_REQUEST, 0x20, 0x0);
		break;
	}

	return rc;
}

int device_shutdown(struct target_session *f)
{
	return -1;
}

static void tcp_srv_event(GServer * srv, GConn * conn, gpointer user_data)
{
	target_accept(&gbls, conn);
}

static int net_init(void)
{
	tcp_srv = gnet_server_new(NULL, 3260, tcp_srv_event, NULL);
	if (!tcp_srv)
		return -1;

	return 0;
}

static void net_exit(void)
{
	gnet_server_unref(tcp_srv);
}

static targv_t  tv_all[4];

static int master_iscsi_init(void)
{
	return target_init(&gbls, tv_all, "MyFirstTarget");
}

static void master_iscsi_exit(void)
{
	target_shutdown(&gbls);
}

int main(int argc, char *argv[])
{
	GMainLoop      *ml;

	ml = g_main_loop_new(NULL, FALSE);
	if (!ml)
		return 1;

	if (net_init())
		return 1;
	if (master_iscsi_init())
		return 1;

	g_main_loop_run(ml);

	master_iscsi_exit();
	net_exit();

	g_main_loop_unref(ml);

	return 0;
}
