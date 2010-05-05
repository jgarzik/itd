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

#ifndef _TARGET_H_
#define _TARGET_H_

#include <stdbool.h>
#include <glib.h>
#include <event.h>

#include "iscsi.h"
#include "iscsiutil.h"
#include "parameters.h"

enum {
	DE_EXTENT,
	DE_DEVICE
};

/* a device can be made up of an extent or another device */
struct disc_de {
	int32_t         type;	/* device or extent */
	uint64_t        size;	/* size of underlying extent or device */
	union {
		struct disc_extent *xp;	/* pointer to extent */
		struct disc_device *dp;	/* pointer to device */
	} u;
};

/* this struct describes an extent of storage */
struct disc_extent {
	char           *extent;	/* extent name */
	char           *dev;	/* device associated with it */
	uint64_t        sacred;	/* offset of extent from start of device */
	uint64_t        len;	/* size of extent */
	int             fd;	/* in-core file descriptor */
	int             used;	/* extent has been used in a device */
};

DEFINE_ARRAY(extv_t, struct disc_extent);

/* this struct describes a device */
struct disc_device {
	char           *dev;	/* device name */
	int             raid;	/* RAID level */
	uint64_t        off;	/* current offset in device */
	uint64_t        len;	/* size of device */
	uint32_t        size;	/* size of device/extent array */
	uint32_t        c;	/* # of entries in device/extents */
	struct disc_de *xv;	/* device/extent array */
	int             used;	/* device has been used in a device/target */
};

DEFINE_ARRAY(devv_t, struct disc_device);

enum {
	TARGET_READONLY = 0x01
};

/* this struct describes an iscsi target's associated features */
struct disc_target {
	char           *target;	/* target name */
	struct disc_de  de;	/* pointer to its device */
	uint16_t        port;	/* port to listen on */
	char           *mask;	/* mask to export it to */
	uint32_t        flags;	/* any flags */
	uint16_t        tsih;	/* target session identifying handle */
	char		*iqn;	/* assigned iqn - can be NULL */
};

DEFINE_ARRAY(targv_t, struct disc_target);

/* Default configuration */

#define DEFAULT_TARGET_MAX_SESSIONS 16	/* n+1 */
#define DEFAULT_TARGET_NUM_LUNS     1
#define DEFAULT_TARGET_BLOCK_LEN    512
#define DEFAULT_TARGET_NUM_BLOCKS   204800
#define DEFAULT_TARGET_NAME         "iqn.1994-04.org.netbsd.iscsi-target"
#define DEFAULT_TARGET_QUEUE_DEPTH  8
#define DEFAULT_TARGET_TCQ          0

enum {
	MAX_TGT_NAME_SIZE = 512,
	MAX_INITIATOR_ADDRESS_SIZE = 256,
	MAX_CONFIG_FILE_NAME = 512,

	ISCSI_IPv4 = AF_INET,
	ISCSI_IPv6 = AF_INET6,
	ISCSI_UNSPEC = PF_UNSPEC,

	MAXSOCK = 8
};

/* global variables, moved from target.c */
struct globals {
	char            targetname[MAX_TGT_NAME_SIZE];	/* name of target */
	uint16_t        port;	/* target port */
	int             state;	/* current state of target */
	char            targetaddress[MAX_TGT_NAME_SIZE];	/* iSCSI TargetAddress */
	targv_t        *tv;	/* array of target devices */
	int             address_family;	/* global default IP address family */
	int             max_sessions;	/* maximum number of sessions */
	uint32_t        last_tsih;	/* the last TSIH that was used */
	GList		*sockets;
	char		host[128];
};

struct server_socket {
	int			fd;
	struct event		ev;
	struct sockaddr		addr;
	socklen_t		addrlen;
	char			addr_str[128];
};

struct target_pdu {
	uint8_t         header[ISCSI_HEADER_LEN];
	unsigned int	hdr_recv;

	uint8_t		*ahs;
	unsigned int	ahs_len;
	unsigned int	ahs_recv;

	uint8_t		*data;
	unsigned int	data_len;
	unsigned int	data_pad_recv;

	unsigned int	pad_len;
};

struct session_xfer {
	unsigned int	desired_len;
	struct iscsi_r2t r2t;
	unsigned int	r2t_flag;
	unsigned int	bytes_recv;
	unsigned int	trans_len;
	int		tag;
	uint8_t		status;
};

enum session_read_state {
	srs_err,
	srs_bhs,
	srs_ahs,
	srs_data_pad,
	srs_exec_pdu,
};

/* session parameters */
struct target_session {
	int             id;
	int             d;
	uint16_t        cid;
	uint32_t        StatSN;
	uint32_t        ExpCmdSN;
	uint32_t        MaxCmdSN;
	int             UsePhaseCollapsedRead;
	int             IsFullFeature;
	int             IsLoggedIn;
	int             LoginStarted;
	uint64_t        isid;
	int             tsih;
	struct globals *globals;
	struct iscsi_parameter *params;
	struct iscsi_sess_param sess_params;
	int             address_family;
	int32_t         last_tsih;
	enum session_read_state readst;

	struct target_pdu pdu;

	struct iscsi_scsi_cmd_args scsi_cmd;

	int		fd;
	struct sockaddr	addr;
	struct event	ev;

	struct tcp_write_state wst;

	struct session_xfer xfer;

	struct list_head sessions_node;

	char            initiator[MAX_INITIATOR_ADDRESS_SIZE];
	char		addr_host[128];
	uint8_t		outbuf[512];
};

struct target_cmd {
	struct iscsi_scsi_cmd_args *scsi_cmd;
};

extern int      target_init(struct globals *, targv_t *, char *);
extern int      target_shutdown(struct globals *);
extern int      target_accept(struct globals *gp, struct server_socket *sock);
extern int      target_sess_cleanup(struct target_session *sess);
extern int      target_transfer_data(struct target_session *,
				     struct iscsi_scsi_cmd_args *,
				     struct iovec *, int);

/*
 * Interface from target to device:
 *
 * device_init() initializes the device
 * device_command() sends a SCSI command to one of the logical units in the device.
 * device_shutdown() shuts down the device.
 */

extern int      device_init(struct globals *, targv_t *, struct disc_target *);
extern int      device_command(struct target_session *, struct target_cmd *);
extern int      device_shutdown(struct target_session *);
extern void     device_set_var(const char *, char *);

#endif /* _TARGET_H_ */
