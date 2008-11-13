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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <glib.h>

#include "iscsi.h"
#include "iscsiutil.h"

/*
 * Task Command
 */

int iscsi_task_cmd_decap(uint8_t * header, struct iscsi_task_cmd *cmd)
{

	RETURN_NOT_EQUAL("Opcode", ISCSI_OPCODE(header), ISCSI_TASK_CMD,
			 NO_CLEANUP, -1);

	cmd->immediate = ((header[0] & 0x40) == 0x40);	/* Immediate bit  */
	cmd->function = header[1] & 0x80;	/* Function  */
	cmd->lun = GUINT64_FROM_BE(*((uint64_t *) (void *)(header + 8)));	/* LUN */
	cmd->tag = ntohl(*((uint32_t *) (void *)(header + 16)));	/* Tag */
	cmd->ref_tag = ntohl(*((uint32_t *) (void *)(header + 20)));	/* Reference Tag */
	cmd->CmdSN = ntohl(*((uint32_t *) (void *)(header + 24)));	/* CmdSN */
	cmd->ExpStatSN = ntohl(*((uint32_t *) (void *)(header + 28)));	/* ExpStatSN */
	cmd->RefCmdSN = ntohl(*((uint32_t *) (void *)(header + 32)));	/* RefCmdSN */
	cmd->ExpDataSN = ntohl(*((uint32_t *) (void *)(header + 36)));	/* ExpDataSN */

	RETURN_NOT_EQUAL("Byte 1, bit 0", header[1] & 0x80, 0x80, NO_CLEANUP,
			 1);
	RETURN_NOT_EQUAL("Byte 2", header[2], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 3", header[3], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 4-7", *((uint32_t *) (void *)(header + 4)), 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 40-43", *((uint32_t *) (void *)(header + 40)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 44-47", *((uint32_t *) (void *)(header + 44)),
			 0, NO_CLEANUP, 1);

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Immediate: %d\n",
		    cmd->immediate);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Function:  %u\n",
		    cmd->function);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:       %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Tag:       %#x\n",
		    cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Ref Tag:   %#x\n",
		    cmd->ref_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "CmdSN:     %u\n",
		    cmd->CmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpStatSN: %u\n",
		    cmd->ExpStatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "RefCmdSN:  %u\n",
		    cmd->RefCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpDataSN: %u\n",
		    cmd->ExpDataSN);

	return 0;
}

/*
 * Task Response
 */

int iscsi_task_rsp_encap(uint8_t * header, struct iscsi_task_rsp *rsp)
{

	uint32_t length;

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Response:  %u\n",
		    rsp->response);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:    %u\n",
		    rsp->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Tag:       %#x\n",
		    rsp->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "StatSN:    %u\n",
		    rsp->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpCmdSN:  %u\n",
		    rsp->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "MaxCmdSN:  %u\n",
		    rsp->MaxCmdSN);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] |= ISCSI_TASK_RSP;	/* Opcode */
	header[1] |= 0x80;	/* Byte 1 bit 0  */
	header[2] = rsp->response;	/* Response */
	length = (rsp->length & 0x00ffffff);	/* Length */
	*((uint32_t *) (void *)(header + 4)) = htonl(length);	/* Length */
	*((uint32_t *) (void *)(header + 16)) = htonl(rsp->tag);	/* Tag */
	*((uint32_t *) (void *)(header + 24)) = htonl(rsp->StatSN);	/* StatSN */
	*((uint32_t *) (void *)(header + 28)) = htonl(rsp->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(rsp->MaxCmdSN);	/* MaxCmdSN */

	return 0;
}

/*
 * NOP-Out
 */

int iscsi_nop_out_decap(uint8_t * header, struct iscsi_nop_out_args *cmd)
{

	RETURN_NOT_EQUAL("Opcode", ISCSI_OPCODE(header), ISCSI_NOP_OUT,
			 NO_CLEANUP, 1);

	cmd->immediate = ((header[0] & 0x40) == 0x40);	/* Immediate bit  */
	cmd->length = ntohl(*((uint32_t *) (void *)(header + 4)));	/* Length */
	cmd->lun = GUINT64_FROM_BE(*((uint64_t *) (void *)(header + 8)));	/* LUN */
	cmd->tag = ntohl(*((uint32_t *) (void *)(header + 16)));	/* Tag */
	cmd->transfer_tag = ntohl(*((uint32_t *) (void *)(header + 20)));	/* Target Tranfer Tag */
	cmd->CmdSN = ntohl(*((uint32_t *) (void *)(header + 24)));	/* CmdSN */
	cmd->ExpStatSN = ntohl(*((uint32_t *) (void *)(header + 28)));	/* ExpStatSN */

	RETURN_NOT_EQUAL("Byte 1", header[1], 0x80, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 2", header[2], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 3", header[3], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 4", header[4], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 32-35", *((uint32_t *) (void *)(header + 32)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 36-39", *((uint32_t *) (void *)(header + 36)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 40-43", *((uint32_t *) (void *)(header + 40)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 44-47", *((uint32_t *) (void *)(header + 44)),
			 0, NO_CLEANUP, 1);

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Immediate:    %d\n",
		    cmd->immediate);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:       %u\n",
		    cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:          %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Tag:          %#x\n",
		    cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Transfer Tag: %#x\n",
		    cmd->transfer_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "CmdSN:        %u\n",
		    cmd->CmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpStatSN:    %u\n",
		    cmd->ExpStatSN);

	return 0;
}

/*
 * NOP-In
 */

int iscsi_nop_in_encap(uint8_t * header, struct iscsi_nop_in_args *cmd)
{
	uint32_t length;

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:       %u\n",
		    cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:          %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Tag:          %#x\n",
		    cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Transfer Tag: %#x\n",
		    cmd->transfer_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "StatSN:       %u\n",
		    cmd->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpCmdSN:     %u\n",
		    cmd->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "MaxCmdSN:     %u\n",
		    cmd->MaxCmdSN);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] = 0x00 | ISCSI_NOP_IN;	/* Opcode  */
	header[1] |= 0x80;	/* Reserved */
	length = (cmd->length & 0x00ffffff);	/* Length */
	*((uint32_t *) (void *)(header + 4)) = htonl(length);	/* Length */
	*((uint64_t *) (void *)(header + 8)) = GUINT64_TO_BE(cmd->lun);	/* LUN */
	*((uint32_t *) (void *)(header + 16)) = htonl(cmd->tag);	/* Tag */
	*((uint32_t *) (void *)(header + 20)) = htonl(cmd->transfer_tag);	/* Target Transfer Tag        */
	*((uint32_t *) (void *)(header + 24)) = htonl(cmd->StatSN);	/* StatSN */
	*((uint32_t *) (void *)(header + 28)) = htonl(cmd->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(cmd->MaxCmdSN);	/* MaxCmdSN */

	return 0;
}

/*
 * Text Command
 */

int iscsi_text_cmd_decap(uint8_t * header, struct iscsi_text_cmd_args *cmd)
{

	RETURN_NOT_EQUAL("Opcode", ISCSI_OPCODE(header), ISCSI_TEXT_CMD,
			 NO_CLEANUP, 1);

	cmd->immediate = ((header[0] & 0x40) == 0x40);	/* Immediate bit  */
	cmd->final = ((header[1] & 0x80) == 0x80);	/* Final bit */
	cmd->cont = ((header[1] & 0x40) == 0x40);	/* Continue bit */
	cmd->length = ntohl(*((uint32_t *) (void *)(header + 4)));	/* Length */
	cmd->lun = GUINT64_FROM_BE(*((uint64_t *) (void *)(header + 8)));	/* LUN */
	cmd->tag = ntohl(*((uint32_t *) (void *)(header + 16)));	/* Tag */
	cmd->transfer_tag = ntohl(*((uint32_t *) (void *)(header + 20)));	/* Transfer Tag */
	cmd->CmdSN = ntohl(*((uint32_t *) (void *)(header + 24)));	/* CmdSN */
	cmd->ExpStatSN = ntohl(*((uint32_t *) (void *)(header + 28)));	/* ExpStatSN */

	RETURN_NOT_EQUAL("Byte 1, Bits 2-7", header[1] & 0x00, 0, NO_CLEANUP,
			 1);
	RETURN_NOT_EQUAL("Byte 2", header[2], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 3", header[3], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 4", header[4], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 8-11", *((uint32_t *) (void *)(header + 8)), 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 12-15", *((uint32_t *) (void *)(header + 12)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 32-35", *((uint32_t *) (void *)(header + 32)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 36-39", *((uint32_t *) (void *)(header + 36)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 40-43", *((uint32_t *) (void *)(header + 40)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 44-47", *((uint32_t *) (void *)(header + 44)),
			 0, NO_CLEANUP, 1);

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Immediate:    %d\n",
		    cmd->immediate);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Final:        %d\n",
		    cmd->final);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Continue:     %d\n",
		    cmd->cont);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:       %u\n",
		    cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:          %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Tag:          %#x\n",
		    cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Transfer Tag: %#x\n",
		    cmd->transfer_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "CmdSN:        %u\n",
		    cmd->CmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpStatSN:    %u\n",
		    cmd->ExpStatSN);

	return 0;
}

/*
 * Text Response
 */

int iscsi_text_rsp_encap(uint8_t * header, struct iscsi_text_rsp_args *rsp)
{
	uint32_t length;

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Final:        %d\n",
		    rsp->final);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Continue:     %d\n",
		    rsp->cont);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:       %u\n",
		    rsp->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:          %" PRIu64 "\n", rsp->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Tag:          %#x\n",
		    rsp->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Transfer Tag: %#x\n",
		    rsp->transfer_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "StatSN:       %u\n",
		    rsp->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpCmdSN:     %u\n",
		    rsp->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "MaxCmdSN:     %u\n",
		    rsp->MaxCmdSN);

	memset(header, 0x0, ISCSI_HEADER_LEN);
	header[0] |= 0x00 | ISCSI_TEXT_RSP;	/* Opcode */
	if (rsp->final) {
		header[1] |= 0x80;	/* Final bit */
	}
	if (rsp->cont) {
		header[1] |= 0x40;	/* Continue */
	}
	length = (rsp->length & 0x00ffffff);	/* Length */
	*((uint32_t *) (void *)(header + 4)) = htonl(length);	/* Length */
	*((uint64_t *) (void *)(header + 8)) = GUINT64_TO_BE(rsp->lun);	/* LUN */
	*((uint32_t *) (void *)(header + 16)) = htonl(rsp->tag);	/* Tag */
	*((uint32_t *) (void *)(header + 20)) = htonl(rsp->transfer_tag);	/* Transfer Tag */
	*((uint32_t *) (void *)(header + 24)) = htonl(rsp->StatSN);	/* StatSN */
	*((uint32_t *) (void *)(header + 28)) = htonl(rsp->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(rsp->MaxCmdSN);	/* MaxCmdSN */

	return 0;
}

/*
 * Login Command
 */

int iscsi_login_cmd_decap(uint8_t * header, struct iscsi_login_cmd_args *cmd)
{

	RETURN_NOT_EQUAL("Opcode", ISCSI_OPCODE(header), ISCSI_LOGIN_CMD,
			 NO_CLEANUP, 1);

	cmd->transit = (header[1] & 0x80) ? 1 : 0;	/* Transit */
	cmd->cont = (header[1] & 0x40) ? 1 : 0;	/* Continue */
	cmd->csg = (header[1] & 0x0cU) >> 2;	/* CSG */
	cmd->nsg = header[1] & 0x03;	/* NSG */
	cmd->version_max = header[2];	/* Version-Max  */
	cmd->version_min = header[3];	/* Version-Min  */
	cmd->AHSlength = header[4];	/* TotalAHSLength */
	cmd->length = ntohl(*((uint32_t *) (void *)(header + 4)));	/* Length */
	cmd->isid = GUINT64_FROM_BE(*((uint64_t *) (void *)(header + 8)));	/* ISID */
	cmd->tsih = ntohs(*((uint16_t *) (void *)(header + 14)));	/* TSIH */
	cmd->tag = ntohl(*((uint32_t *) (void *)(header + 16)));	/* Task Tag */
	cmd->cid = ntohs(*((uint16_t *) (void *)(header + 20)));	/* CID */
	cmd->CmdSN = ntohl(*((uint32_t *) (void *)(header + 24)));	/* CmdSN  */
	cmd->ExpStatSN = ntohl(*((uint32_t *) (void *)(header + 28)));	/* ExpStatSN */

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Transit:           %d\n", cmd->transit);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Continue:          %d\n", cmd->cont);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "CSG:               %u\n", cmd->csg);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "NSG:               %u\n", cmd->nsg);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Version_min:       %u\n", cmd->version_min);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Version_max:       %u\n", cmd->version_max);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "TotalAHSLength:    %u\n", cmd->AHSlength);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSegmentLength: %u\n", cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ISID:              %" PRIu64 "\n", cmd->isid);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "TSIH:              %hu\n", cmd->tsih);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Task Tag:          %#x\n", cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "CID:               %hu\n", cmd->cid);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "CmdSN:             %u\n", cmd->CmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ExpStatSN:         %u\n", cmd->ExpStatSN);

	RETURN_NOT_EQUAL("Byte 1, bits 2-3", (header[1] & 0x30U) >> 4U, 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 22-23", *((uint16_t *) (void *)(header + 22)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 32-35", *((uint32_t *) (void *)(header + 32)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 36-39", *((uint32_t *) (void *)(header + 36)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 40-43", *((uint32_t *) (void *)(header + 40)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 44-47", *((uint32_t *) (void *)(header + 44)),
			 0, NO_CLEANUP, 1);

	if (cmd->transit) {
		if (cmd->nsg <= cmd->csg) {
			return -1;
		}
		if ((cmd->nsg != 0) && (cmd->nsg != 1) && (cmd->nsg != 3)) {
			return -1;
		}
	}
	return 0;
}

/*
 * Login Response
 */

int iscsi_login_rsp_encap(uint8_t * header, struct iscsi_login_rsp_args *rsp)
{

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Transit:           %d\n", rsp->transit);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Continue:          %d\n", rsp->cont);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "CSG:               %u\n", rsp->csg);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "NSG:               %u\n", rsp->nsg);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Version_max:       %u\n", rsp->version_max);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Version_active:    %u\n", rsp->version_active);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "TotalAHSLength:    %u\n", rsp->AHSlength);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSegmentLength: %u\n", rsp->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ISID:              %" PRIu64 "\n", rsp->isid);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "TSIH:              %u\n", rsp->tsih);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Task Tag:          %#x\n", rsp->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "StatSN:            %u\n", rsp->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ExpCmdSN:          %u\n", rsp->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "MaxCmdSN:          %u\n", rsp->MaxCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Status-Class:      %u\n", rsp->status_class);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Status-Detail:     %u\n", rsp->status_detail);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] |= 0x00 | ISCSI_LOGIN_RSP;	/* Opcode  */
	if (rsp->transit) {
		header[1] |= 0x80;	/* Transit  */
	}
	if (rsp->cont) {
		header[1] |= 0x40;	/* Continue */
	}
	header[1] |= ((rsp->csg) << 2) & 0x0c;	/* CSG */
	if (rsp->transit) {
		header[1] |= (rsp->nsg) & 0x03;	/* NSG */
	}
	header[2] = rsp->version_max;	/* Version-max */
	header[3] = rsp->version_active;	/* Version-active */
	header[4] = rsp->AHSlength;	/* TotalAHSLength */
	*((uint32_t *) (void *)(header + 4)) = htonl(rsp->length);	/* Length */
	*((uint64_t *) (void *)(header + 8)) = GUINT64_TO_BE(rsp->isid);	/* ISID */
	*((uint16_t *) (void *)(header + 14)) = htons(rsp->tsih);	/* TSIH */
	*((uint32_t *) (void *)(header + 16)) = htonl(rsp->tag);	/* Tag  */
	*((uint32_t *) (void *)(header + 24)) = htonl(rsp->StatSN);	/* StatRn */
	*((uint32_t *) (void *)(header + 28)) = htonl(rsp->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(rsp->MaxCmdSN);	/* MaxCmdSN */
	header[36] = rsp->status_class;	/* Status-Class */
	header[37] = rsp->status_detail;	/* Status-Detail */

	return 0;
}

/*
 * Logout Command
 */

int iscsi_logout_cmd_decap(uint8_t * header, struct iscsi_logout_cmd_args *cmd)
{

	RETURN_NOT_EQUAL("Opcode", ISCSI_OPCODE(header), ISCSI_LOGOUT_CMD,
			 NO_CLEANUP, 1);

	cmd->immediate = (header[0] & 0x40) ? 1 : 0;	/* Immediate */
	cmd->reason = header[1] & 0x7f;	/* Reason */
	cmd->tag = ntohl(*((uint32_t *) (void *)(header + 16)));	/* Tag */
	cmd->cid = ntohs(*((uint16_t *) (void *)(header + 20)));	/* CID */
	cmd->CmdSN = ntohl(*((uint32_t *) (void *)(header + 24)));	/* CmdSN */
	cmd->ExpStatSN = ntohl(*((uint32_t *) (void *)(header + 28)));	/* ExpStatSN */

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Immediate: %d\n",
		    cmd->immediate);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Reason:    %u\n",
		    cmd->reason);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Task Tag:  %#x\n",
		    cmd->tag);

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "CID:       %hu\n",
		    cmd->cid);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "CmdSN:     %u\n",
		    cmd->CmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpStatSN: %u\n",
		    cmd->ExpStatSN);

	RETURN_NOT_EQUAL("Byte 0 bit 0", (unsigned)(header[0]) >> 7U, 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 1 bit 0", (unsigned)(header[1]) >> 7U, 1,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 2", header[2], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 3", header[3], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 4-7", *((uint32_t *) (void *)(header + 4)), 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 8-11", *((uint32_t *) (void *)(header + 8)), 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 12-15", *((uint32_t *) (void *)(header + 12)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 22-23", *((uint16_t *) (void *)(header + 22)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 32-35", *((uint32_t *) (void *)(header + 32)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 36-39", *((uint32_t *) (void *)(header + 36)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 40-43", *((uint32_t *) (void *)(header + 40)),
			 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Bytes 44-47", *((uint32_t *) (void *)(header + 44)),
			 0, NO_CLEANUP, 1);

	return 0;
}

/*
 * Logout Response
 */

int iscsi_logout_rsp_encap(uint8_t * header, struct iscsi_logout_rsp_args *rsp)
{

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Response:    %u\n",
		    rsp->response);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:      %u\n",
		    rsp->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Task Tag:    %#x\n",
		    rsp->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "StatSN:      %u\n",
		    rsp->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpCmdSN:    %u\n",
		    rsp->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "MaxCmdSN:    %u\n",
		    rsp->MaxCmdSN);

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Time2Wait:   %hu\n",
		    rsp->Time2Wait);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Time2Retain: %hu\n",
		    rsp->Time2Retain);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] |= 0x00 | ISCSI_LOGOUT_RSP;	/* Opcode  */
	header[1] |= 0x80;	/* Reserved  */
	header[2] = rsp->response;	/* Response */
	*((uint32_t *) (void *)(header + 4)) = htonl(rsp->length);	/* Length */
	*((uint32_t *) (void *)(header + 16)) = htonl(rsp->tag);	/* Tag */
	*((uint32_t *) (void *)(header + 24)) = htonl(rsp->StatSN);	/* StatSN */
	*((uint32_t *) (void *)(header + 28)) = htonl(rsp->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(rsp->MaxCmdSN);	/* MaxCmdSN */
	*((uint16_t *) (void *)(header + 40)) = htons(rsp->Time2Wait);	/* Time2Wait */
	*((uint16_t *) (void *)(header + 42)) = htons(rsp->Time2Retain);	/* Time2Retain */

	return 0;
}

/*
 * SCSI Command
 */

int iscsi_scsi_cmd_decap(uint8_t * header, struct iscsi_scsi_cmd_args *cmd)
{

	RETURN_NOT_EQUAL("Opcode", ISCSI_OPCODE(header), ISCSI_SCSI_CMD,
			 NO_CLEANUP, 1);

	cmd->immediate = (header[0] & 0x40) ? 1 : 0;	/* Immediate */
	cmd->final = (header[1] & 0x80) ? 1 : 0;	/* Final */
	cmd->input = (header[1] & 0x40) ? 1 : 0;	/* Input */
	cmd->output = (header[1] & 0x20) ? 1 : 0;	/* Output */
	cmd->attr = header[1] & 0x07;	/* ATTR  */
	cmd->ahs_len = header[4];
	header[4] = 0x00;
	cmd->length = ntohl(*((uint32_t *) (void *)(header + 4)));	/* DataSegmentLength */
	cmd->lun = GUINT64_FROM_BE(*((uint64_t *) (void *)(header + 8)));	/* LUN */
	cmd->tag = ntohl(*((uint32_t *) (void *)(header + 16)));	/* Task Tag */
	cmd->trans_len = ntohl(*((uint32_t *) (void *)(header + 20)));	/* Expected Transfer
									 * Length */
	cmd->CmdSN = ntohl(*((uint32_t *) (void *)(header + 24)));	/* CmdSN  */
	cmd->ExpStatSN = ntohl(*((uint32_t *) (void *)(header + 28)));	/* ExpStatSN */
	cmd->cdb = header + 32;	/* CDB */

	RETURN_NOT_EQUAL("Byte 1, Bits 3-4", header[1] & 0x18, 0, NO_CLEANUP,
			 -1);
	RETURN_NOT_EQUAL("Byte 2", header[2], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 3", header[3], 0, NO_CLEANUP, 1);

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Immediate:         %d\n", cmd->immediate);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Final:             %d\n", cmd->final);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Input:             %d\n", cmd->input);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Output:            %d\n", cmd->output);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ATTR:              %d\n", cmd->attr);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "TotalAHSLength:    %u\n", cmd->ahs_len);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSegmentLength: %u\n", cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:               %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Task Tag:          %#x\n", cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Transfer Length:   %u\n", cmd->trans_len);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "CmdSN:             %u\n", cmd->CmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ExpStatSN:         %u\n", cmd->ExpStatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "CDB:               %#x\n", cmd->cdb[0]);

	return 0;
}

/*
 * SCSI Response
 */

int iscsi_scsi_rsp_encap(uint8_t * header, struct iscsi_scsi_rsp *rsp)
{

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Bidi Overflow:       %d\n", rsp->bidi_overflow);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Bidi Underflow:      %d\n", rsp->bidi_underflow);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Overflow:            %d\n", rsp->overflow);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Underflow:           %d\n", rsp->underflow);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "iSCSI Response:      %u\n", rsp->response);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "SCSI Status:         %u\n", rsp->status);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSegmentLength:   %u\n", rsp->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Task Tag:            %#x\n", rsp->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "StatSN:              %u\n", rsp->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ExpCmdSN:            %u\n", rsp->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "MaxCmdSN:            %u\n", rsp->MaxCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ExpDataSN:           %u\n", rsp->ExpDataSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Bidi Residual Count: %u\n", rsp->bidi_res_cnt);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Residual Count:      %u\n", rsp->basic_res_cnt);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] |= 0x00 | ISCSI_SCSI_RSP;	/* Opcode  */
	header[1] |= 0x80;	/* Byte 1 bit 7 */
	if (rsp->bidi_overflow) {
		header[1] |= 0x10;	/* Bidi overflow */
	}
	if (rsp->bidi_underflow) {
		header[1] |= 0x08;	/* Bidi underflow */
	}
	if (rsp->overflow) {
		header[1] |= 0x04;	/* Overflow */
	}
	if (rsp->underflow) {
		header[1] |= 0x02;	/* Underflow  */
	}
	header[2] = rsp->response;	/* iSCSI Response */
	header[3] = rsp->status;	/* SCSI Status */
	header[4] = rsp->ahs_len;	/* TotalAHSLength  */
	*((uint32_t *) (void *)(header + 4)) = htonl(rsp->length);	/* DataSegmentLength */
	*((uint32_t *) (void *)(header + 16)) = htonl(rsp->tag);	/* Task Tag */
	*((uint32_t *) (void *)(header + 24)) = htonl(rsp->StatSN);	/* StatSN */
	*((uint32_t *) (void *)(header + 28)) = htonl(rsp->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(rsp->MaxCmdSN);	/* MaxCmdSN */
	*((uint32_t *) (void *)(header + 36)) = htonl(rsp->ExpDataSN);	/* ExpDataSN  */
	*((uint32_t *) (void *)(header + 40)) = htonl(rsp->bidi_res_cnt);	/* Bidi Residual Count */
	*((uint32_t *) (void *)(header + 44)) = htonl(rsp->basic_res_cnt);	/* Residual Count */

	return 0;
}

/*
 * Ready To Transfer
 */

int iscsi_r2t_encap(uint8_t * header, struct iscsi_r2t *cmd)
{
	uint32_t length;

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "TotalAHSLength:    %u\n", cmd->AHSlength);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:          %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Tag:          %#x\n",
		    cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Transfer Tag: %#x\n",
		    cmd->transfer_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "StatSN:       %u\n",
		    cmd->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpCmdSN:     %u\n",
		    cmd->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "MaxCmdSN:     %u\n",
		    cmd->MaxCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "R2TSN:        %u\n",
		    cmd->R2TSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Offset:       %u\n",
		    cmd->offset);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:       %u\n",
		    cmd->length);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] |= 0x00 | ISCSI_R2T;	/* Opcode  */
	header[1] |= 0x80;
	length = (cmd->AHSlength & 0x00ffffff);	/* AHSLength */
	*((uint32_t *) (void *)(header + 4)) = htonl(length);	/* AHSLength */
	*((uint64_t *) (void *)(header + 8)) = GUINT64_TO_BE(cmd->lun);	/* LUN */
	*((uint32_t *) (void *)(header + 16)) = htonl(cmd->tag);	/* Tag */
	*((uint32_t *) (void *)(header + 20)) = htonl(cmd->transfer_tag);	/* Transfer Tag */
	*((uint32_t *) (void *)(header + 24)) = htonl(cmd->StatSN);	/* StatSN  */
	*((uint32_t *) (void *)(header + 28)) = htonl(cmd->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(cmd->MaxCmdSN);	/* MaxCmdSN */
	*((uint32_t *) (void *)(header + 36)) = htonl(cmd->R2TSN);	/* R2TSN */
	*((uint32_t *) (void *)(header + 40)) = htonl(cmd->offset);	/* Buffer Offset */
	*((uint32_t *) (void *)(header + 44)) = htonl(cmd->length);	/* Transfer Length */

	return 0;
}

/*
 * SCSI Write Data
 */

int iscsi_write_data_decap(uint8_t * header, struct iscsi_write_data *cmd)
{

	RETURN_NOT_EQUAL("Opcode", ISCSI_OPCODE(header), ISCSI_WRITE_DATA,
			 NO_CLEANUP, 1);

	cmd->final = (header[1] & 0x80) ? 1 : 0;	/* Final */
	cmd->length = ntohl(*((uint32_t *) (void *)(header + 4)));	/* Length */
	cmd->lun = GUINT64_FROM_BE(*((uint64_t *) (void *)(header + 8)));	/* LUN */
	cmd->tag = ntohl(*((uint32_t *) (void *)(header + 16)));	/* Tag */
	cmd->transfer_tag = ntohl(*((uint32_t *) (void *)(header + 20)));	/* Transfer Tag */
	cmd->ExpStatSN = ntohl(*((uint32_t *) (void *)(header + 28)));	/* ExpStatSN  */
	cmd->DataSN = ntohl(*((uint32_t *) (void *)(header + 36)));	/* DataSN    */
	cmd->offset = ntohl(*((uint32_t *) (void *)(header + 40)));	/* Buffer Offset */

	RETURN_NOT_EQUAL("Byte 1, Bits 1-7", header[1] & 0x7f, 0, NO_CLEANUP,
			 1);
	RETURN_NOT_EQUAL("Byte 2", header[2], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 3", header[3], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 4", header[4], 0, NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 24-27", *((uint32_t *) (void *)(header + 24)), 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 32-35", *((uint32_t *) (void *)(header + 32)), 0,
			 NO_CLEANUP, 1);
	RETURN_NOT_EQUAL("Byte 44-47", *((uint32_t *) (void *)(header + 44)), 0,
			 NO_CLEANUP, 1);

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Final:              %u\n", cmd->final);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSegmentLength:  %u\n", cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:                %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Task Tag:           %#x\n", cmd->tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Transfer Tag:       %#x\n", cmd->transfer_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ExpStatSN:          %u\n", cmd->ExpStatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSN:             %u\n", cmd->DataSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Buffer Offset:      %u\n", cmd->offset);

	return 0;
}

/*
 * SCSI Read Data
 */

int iscsi_read_data_encap(uint8_t * header, struct iscsi_read_data *cmd)
{

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Final:             %d\n", cmd->final);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Acknowledge:       %d\n", cmd->ack);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Overflow:          %d\n", cmd->overflow);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Underflow:         %d\n", cmd->underflow);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "S_bit:             %d\n", cmd->S_bit);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Status:            %u\n", cmd->status);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSegmentLength: %u\n", cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "LUN:               %" PRIu64 "\n", cmd->lun);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Task Tag:          %#x\n", cmd->task_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Transfer Tag:      %#x\n", cmd->transfer_tag);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "StatSN:            %u\n", cmd->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "ExpCmdSN:          %u\n", cmd->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "MaxCmdSN:          %u\n", cmd->MaxCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "DataSN:            %u\n", cmd->DataSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Buffer Offset      %u\n", cmd->offset);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__,
		    "Residual Count:    %u\n", cmd->res_count);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] = 0x00 | ISCSI_READ_DATA;	/* Opcode  */
	if (cmd->final) {
		header[1] |= 0x80;	/* Final */
	}
	if (cmd->ack) {
		header[1] |= 0x40;	/* ACK */
	}
	if (cmd->overflow) {
		header[1] |= 0x04;	/* Overflow  */
	}
	if (cmd->underflow) {
		header[1] |= 0x02;	/* Underflow */
	}
	if (cmd->S_bit) {
		header[1] |= 0x01;	/* S Bit */
	}
	if (cmd->S_bit) {
		header[3] = cmd->status;	/* Status  */
	}
	*((uint32_t *) (void *)(header + 4)) = htonl(cmd->length);	/* Length */
	*((uint64_t *) (void *)(header + 8)) = GUINT64_TO_BE(cmd->lun);	/* LUN */
	*((uint32_t *) (void *)(header + 16)) = htonl(cmd->task_tag);	/* Task Tag */
	*((uint32_t *) (void *)(header + 20)) = htonl(cmd->transfer_tag);	/* Transfer Tag */
	if (cmd->S_bit) {
		*((uint32_t *) (void *)(header + 24)) = htonl(cmd->StatSN);	/* StatSN */
	}
	*((uint32_t *) (void *)(header + 28)) = htonl(cmd->ExpCmdSN);	/* ExpCmdSN  */
	*((uint32_t *) (void *)(header + 32)) = htonl(cmd->MaxCmdSN);	/* MaxCmdSN  */
	*((uint32_t *) (void *)(header + 36)) = htonl(cmd->DataSN);	/* DataSN  */
	*((uint32_t *) (void *)(header + 40)) = htonl(cmd->offset);	/* Buffer Offset */
	if (cmd->S_bit) {
		*((uint32_t *) (void *)(header + 44)) = htonl(cmd->res_count);	/* Residual Count  */
	}

	return 0;
}

/*
 * Reject
 */

int iscsi_reject_encap(uint8_t * header, struct iscsi_reject *cmd)
{

	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Reason:   %u\n",
		    cmd->reason);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "Length:   %u\n",
		    cmd->length);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "StatSN:   %u\n",
		    cmd->StatSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "ExpCmdSN: %u\n",
		    cmd->ExpCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "MaxCmdSN: %u\n",
		    cmd->MaxCmdSN);
	iscsi_trace(TRACE_ISCSI_ARGS, __FILE__, __LINE__, "DataSN:   %u\n",
		    cmd->DataSN);

	memset(header, 0x0, ISCSI_HEADER_LEN);

	header[0] |= 0x00 | ISCSI_REJECT;	/* Opcode  */
	header[1] |= 0x80;
	header[2] = cmd->reason;	/* Reason */
	*((uint32_t *) (void *)(header + 4)) = htonl(cmd->length);	/* Length  */
	*((uint32_t *) (void *)(header + 24)) = htonl(cmd->StatSN);	/* StatSN */
	*((uint32_t *) (void *)(header + 28)) = htonl(cmd->ExpCmdSN);	/* ExpCmdSN */
	*((uint32_t *) (void *)(header + 32)) = htonl(cmd->MaxCmdSN);	/* MaxCmdSN */
	*((uint32_t *) (void *)(header + 36)) = htonl(cmd->DataSN);	/* DataSN */

	return 0;
}
