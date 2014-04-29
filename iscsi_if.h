/*
 * iSCSI User/Kernel Interface
 *
 * Copyright (C) 2005 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#ifndef ISCSI_IF_H
#define ISCSI_IF_H

#include "iscsi_proto.h"
#include "config.h"

#define ISCSI_TRANSPORT_NAME_MAXLEN	64
#define ISCSI_TRANSPORT_MAX		16
#define UEVENT_BASE			10
#define KEVENT_BASE			100
#define ISCSI_ERR_BASE			1000

/*
 * Common error codes
 */
typedef enum {
	ISCSI_OK			= 0,

	ISCSI_ERR_BAD_TARGET		= ISCSI_ERR_BASE + 1,
	ISCSI_ERR_DATASN		= ISCSI_ERR_BASE + 2,
	ISCSI_ERR_DATA_OFFSET		= ISCSI_ERR_BASE + 3,
	ISCSI_ERR_MAX_CMDSN		= ISCSI_ERR_BASE + 4,
	ISCSI_ERR_EXP_CMDSN		= ISCSI_ERR_BASE + 5,
	ISCSI_ERR_BAD_OPCODE		= ISCSI_ERR_BASE + 6,
	ISCSI_ERR_DATALEN		= ISCSI_ERR_BASE + 7,
	ISCSI_ERR_AHSLEN		= ISCSI_ERR_BASE + 8,
	ISCSI_ERR_PROTO			= ISCSI_ERR_BASE + 9,
	ISCSI_ERR_LUN			= ISCSI_ERR_BASE + 10,
	ISCSI_ERR_BAD_ITT		= ISCSI_ERR_BASE + 11,
	ISCSI_ERR_CNX_FAILED		= ISCSI_ERR_BASE + 12,
	ISCSI_ERR_R2TSN			= ISCSI_ERR_BASE + 13,
	ISCSI_ERR_SNX_FAILED		= ISCSI_ERR_BASE + 14,
	ISCSI_ERR_HDR_DGST		= ISCSI_ERR_BASE + 15,
	ISCSI_ERR_DATA_DGST		= ISCSI_ERR_BASE + 16,
	ISCSI_ERR_PDU_GATHER_FAILED	= ISCSI_ERR_BASE + 17,
} iscsi_err_e;

/*
 * iSCSI Parameters (RFC3720)
 */
typedef enum {
	ISCSI_PARAM_MAX_RECV_DLENGTH	= 0,
	ISCSI_PARAM_MAX_XMIT_DLENGTH	= 1,
	ISCSI_PARAM_HDRDGST_EN		= 2,
	ISCSI_PARAM_DATADGST_EN		= 3,
	ISCSI_PARAM_INITIAL_R2T_EN	= 4,
	ISCSI_PARAM_MAX_R2T		= 5,
	ISCSI_PARAM_IMM_DATA_EN		= 6,
	ISCSI_PARAM_FIRST_BURST		= 7,
	ISCSI_PARAM_MAX_BURST		= 8,
	ISCSI_PARAM_PDU_INORDER_EN	= 9,
	ISCSI_PARAM_DATASEQ_INORDER_EN	= 10,
	ISCSI_PARAM_ERL			= 11,
	ISCSI_PARAM_IFMARKER_EN		= 12,
	ISCSI_PARAM_OFMARKER_EN		= 13,
} iscsi_param_e;

typedef uint64_t iscsi_snx_h;		/* iSCSI Data-Path session handle */
typedef uint64_t iscsi_cnx_h;		/* iSCSI Data-Path connection handle */

#define iscsi_ptr(_handle) ((void*)(unsigned long)_handle)
#define iscsi_handle(_ptr) ((uint64_t)(unsigned long)_ptr)

/*
 * These flags presents iSCSI Data-Path capabilities.
 */
#define CAP_RECOVERY_L0		0x1
#define CAP_RECOVERY_L1		0x2
#define CAP_RECOVERY_L2		0x4
#define CAP_MULTI_R2T		0x8
#define CAP_HDRDGST		0x10
#define CAP_DATADGST		0x20
#define CAP_MULTI_CNX		0x40
#define CAP_TEXT_NEGO		0x80

/**
 * struct iscsi_transport - down calls
 *
 * @name: transport name
 * @caps: iSCSI Data-Path capabilities
 * @create_snx: create new iSCSI session object
 * @destroy_snx: destroy existing iSCSI session object
 * @create_cnx: create new iSCSI connection
 * @bind_cnx: associate this connection with existing iSCSI session and
 *            specified transport descriptor
 * @destroy_cnx: destroy inactive iSCSI connection
 * @set_param: set iSCSI Data-Path operational parameter
 * @start_cnx: set connection to be operational
 * @stop_cnx: suspend connection
 * @send_pdu: send iSCSI PDU, Login, Logout, NOP-Out, Reject, Text.
 *
 * API provided by generic iSCSI Data Path module
 */
 
/*struct iscsi_transport {
	char            *name;
	unsigned int    caps;
	unsigned int    max_cnx;
	iscsi_snx_h (*create_session) (iscsi_snx_h cp_snx,
			uint32_t initial_cmdsn, uint32_t *sid);
	void (*destroy_session) (iscsi_snx_h dp_snx);
	iscsi_cnx_h (*create_cnx) (iscsi_snx_h dp_snx, iscsi_cnx_h cp_cnx,
			uint32_t cid);
	int (*bind_cnx) (iscsi_snx_h dp_snx, iscsi_cnx_h dp_cnx,
			uint32_t transport_fd, int is_leading);
	int (*start_cnx) (iscsi_cnx_h dp_cnx);
	void (*stop_cnx) (iscsi_cnx_h dp_cnx);
	void (*destroy_cnx) (iscsi_cnx_h dp_cnx);
	int (*set_param) (iscsi_cnx_h dp_cnx, iscsi_param_e param,
			  uint32_t value);
	int (*send_pdu) (iscsi_cnx_h dp_cnx, struct iscsi_hdr *hdr,
			 char *data, uint32_t data_size);
};*/

/*
 * up calls
 */
//int iscsi_register_transport(struct iscsi_transport *ops, int id);
//void iscsi_unregister_transport(int id);
int iscsi_control_recv_pdu(iscsi_cnx_h cp_cnx, struct iscsi_hdr *hdr, char *data, uint32_t data_size);
//void iscsi_control_cnx_error(iscsi_cnx_h cp_cnx, iscsi_err_e error);

#endif
