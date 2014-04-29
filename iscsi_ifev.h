/*
 * iSCSI Kernel/User Interface Events
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

#ifndef ISCSI_IFEV_H
#define ISCSI_IFEV_H

typedef enum iscsi_uevent_e {
	ISCSI_UEVENT_UNKNOWN		= 0,

	/* down events */
	ISCSI_UEVENT_CREATE_SESSION	= UEVENT_BASE + 1,
	ISCSI_UEVENT_DESTROY_SESSION	= UEVENT_BASE + 2,
	ISCSI_UEVENT_CREATE_CNX		= UEVENT_BASE + 3,
	ISCSI_UEVENT_DESTROY_CNX	= UEVENT_BASE + 4,
	ISCSI_UEVENT_BIND_CNX		= UEVENT_BASE + 5,
	ISCSI_UEVENT_SET_PARAM		= UEVENT_BASE + 6,
	ISCSI_UEVENT_START_CNX		= UEVENT_BASE + 7,
	ISCSI_UEVENT_STOP_CNX		= UEVENT_BASE + 8,
	ISCSI_UEVENT_SEND_PDU		= UEVENT_BASE + 9,

	/* up events */
	ISCSI_KEVENT_RECV_PDU		= KEVENT_BASE + 1,
	ISCSI_KEVENT_CNX_ERROR		= KEVENT_BASE + 2,
} iscsi_uevent_e;

struct iscsi_uevent {
	uint32_t type; /* k/u events type */
	uint32_t transport_id;

	union {
		/* messages u -> k */
		struct msg_create_session {
			uint64_t	session_handle;
			uint32_t	initial_cmdsn;
		} c_session;
		struct msg_destroy_session {
			uint64_t	session_handle;
		} d_session;
		struct msg_create_cnx {
			uint64_t	session_handle;
			uint64_t	cnx_handle;
			uint32_t	cid;
		} c_cnx;
		struct msg_bind_cnx {
			uint64_t	session_handle;
			uint64_t	cnx_handle;
			uint32_t	transport_fd;
			uint32_t	is_leading;
		} b_cnx;
		struct msg_destroy_cnx {
			uint64_t	cnx_handle;
		} d_cnx;
		struct msg_send_pdu {
			uint32_t	hdr_size;
			uint32_t	data_size;
			uint64_t	cnx_handle;
		} send_pdu;
		struct msg_set_param {
			uint64_t	cnx_handle;
			uint32_t	param; /* iscsi_param_e */
			uint32_t	value;
		} set_param;
		struct msg_start_cnx {
			uint64_t	cnx_handle;
		} start_cnx;
		struct msg_stop_cnx {
			uint64_t	cnx_handle;
		} stop_cnx;
	} u;
	union {
		/* messages k -> u */
		uint64_t		handle;
		int			retcode;
		struct msg_create_session_ret {
			uint64_t	handle;
			uint32_t	sid;
		} c_session_ret;
		struct msg_recv_req {
			uint64_t	recv_handle;
			uint64_t	cnx_handle;
		} recv_req;
		struct msg_cnx_error {
			uint64_t	cnx_handle;
			uint32_t	error; /* iscsi_err_e */
		} cnxerror;
	} r;
};

#endif /* ISCSI_IFEV_H */
