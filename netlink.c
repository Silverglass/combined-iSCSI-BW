/*
 * iSCSI Netlink/Linux Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
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
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "cvm-common-errno.h"

#include "cvmx-config.h"
#include "global-config.h"

#include "cvmx.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-spinlock.h"
#include "cvmx-malloc.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-if-var.h"

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#endif
#include "socket.h"
#include "socketvar.h"

#include "cvm-tcp-var.h"

#include "cvm-socket.h"


//#include <asm/types.h>
//#include <sys/socket.h>
//#include <sys/types.h>
//#include <linux/netlink.h>

#include "iscsi_if.h"
#include "iscsi_ifev.h"
#include "iscsi_tcp.h"
#include "initiator.h"
//#include "iscsid.h"
//#include "log.h"





//static struct sockaddr_nl src_addr, dest_addr;
static void *xmitbuf = NULL;
static int xmitlen = 0;
static void *recvbuf = NULL;
static int recvlen = 0;

#ifdef NL
int
ctldev_read(int ctrl_fd, char *data, int count)
{
	memcpy(data, recvbuf + recvlen, count);
	recvlen += count;
	return count;
}

static int
nl_read(int ctrl_fd, struct nlmsghdr *nl, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = nl;
	iov.iov_len = sizeof(*nl);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	return rc;
}

static int
nlpayload_read(int ctrl_fd, char *data, int count, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = calloc(1, NLMSG_SPACE(count));
	if (!iov.iov_base)
		return -ENOMEM;
	iov.iov_len = NLMSG_SPACE(count);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	memcpy(data, NLMSG_DATA(iov.iov_base), count);

	free(iov.iov_base);

	return rc;
}


static int
__ksession_call(int ctrl_fd, void *iov_base, int iov_len)
{
	int rc;
	struct iovec iov;
	struct iscsi_uevent *ev = iov_base;
	iscsi_uevent_e type = ev->type;

	iov.iov_base = iov_base;
	iov.iov_len = iov_len;

	if ((rc = ctldev_writev(ctrl_fd, type, &iov, 1)) < 0) {
		return rc;
	}

	do {
		if ((rc = nlpayload_read(ctrl_fd, (void*)ev,
					 sizeof(*ev), MSG_PEEK)) < 0) {
			return rc;
		}
		if (ev->type != type) {
			/*
			 * receive and queue async. event which as of
			 * today could be:
			 *	- CNX_ERROR
			 *	- RECV_PDU
			 */
			ctldev_handle(ctrl_fd);
		} else {
			if ((rc = nlpayload_read(ctrl_fd, (void*)ev,
						 sizeof(*ev), 0)) < 0) {
				return rc;
			}
			break;
		}
	} while (ev->type != type);

	return rc;
}



int
ksession_destroy(int ctrl_fd, uiscsi_session_t *session)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.d_session.session_handle = session->handle;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't destroy session with id = %d (%d)",
			  session->id, errno);
		return rc;
	}

	log_warning("destroyed iSCSI session, handle 0x%p",
		  (void*)session->handle);

	return 0;
}

int
ksession_cnx_destroy(int ctrl_fd, uiscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.d_cnx.cnx_handle = conn->handle;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't destroy cnx with id = %d (%d)",
			  conn->id, errno);
		return rc;
	}

	log_warning("destroyed iSCSI connection, handle 0x%p",
		  (void*)conn->handle);
	return 0;
}


int
ksession_stop_cnx(int ctrl_fd, uiscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.stop_cnx.cnx_handle = conn->handle;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't stop connection 0x%p with "
			  "id = %d (%d)", (void*)conn->handle,
			  conn->id, errno);
		return rc;
	}

	log_debug(3, "connection 0x%p is stopped now",
			(void*)conn->handle);
	return 0;
}


int
ctldev_handle(int ctrl_fd)
{
	int rc;
	struct iscsi_uevent *ev;
	struct qelem *item;
	uiscsi_session_t *session = NULL;
	uiscsi_conn_t *conn = NULL;
	unsigned long recv_handle;
	struct nlmsghdr nlh;
	int ev_size;

	if ((rc = nl_read(ctrl_fd, &nlh, MSG_PEEK)) < 0) {
		log_error("can not read nlmsghdr, error %d", rc);
		return rc;
	}

	ev_size = nlh.nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
	recv_handle = (unsigned long)calloc(1, ev_size);
	if (!recv_handle) {
		log_error("can not allocate memory for receive handle");
		return -ENOMEM;
	}

	log_debug(6, "message real length is %d bytes, recv_handle %p",
		nlh.nlmsg_len, (void*)recv_handle);

	if ((rc = nlpayload_read(ctrl_fd, (void*)recv_handle,
				ev_size, 0)) < 0) {
		log_error("can not read from NL socket, error %d", rc);
		return rc;
	}
	ev = (struct iscsi_uevent *)recv_handle;

	/* verify connection */
	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		int i;
		session = (uiscsi_session_t *)item;
		for (i=0; i<ISCSI_CNX_MAX; i++) {
			if (&session->cnx[i] == (uiscsi_conn_t*)
					iscsi_ptr(ev->r.recv_req.cnx_handle) ||
			    &session->cnx[i] == (uiscsi_conn_t*)
					iscsi_ptr(ev->r.cnxerror.cnx_handle)) {
				conn = &session->cnx[i];
				break;
			}
		}
		item = item->q_forw;
	}

	if (ev->type == ISCSI_KEVENT_RECV_PDU) {
		if (conn == NULL) {
			log_error("could not verify connection 0x%p for "
				  "event RECV_PDU", conn);
			return -ENXIO;
		}

		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_RECV_PDU, conn,
			sizeof(unsigned long), &recv_handle);
		actor_schedule(&session->mainloop);

	} else if (ev->type == ISCSI_KEVENT_CNX_ERROR) {
		if (conn == NULL) {
			log_error("could not verify connection 0x%p for "
				  "event CNX_ERR", conn);
			return -ENXIO;
		}

		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_ERROR, conn,
			sizeof(unsigned long), (void*)&ev->r.cnxerror.error);
		actor_schedule(&session->mainloop);

	} else {
		log_error("unknown kernel event %d", ev->type);
		return -EEXIST;
	}

	return 0;
}

int ctldev_open(void)
{
	int ctrl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if (!ctrl_fd) {
		log_error("can not create NETLINK_ISCSI socket");
		return -1;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0; /* not in mcast groups */
	if (bind(ctrl_fd, (struct sockaddr *)&src_addr, sizeof(src_addr))) {
		log_error("can not bind NETLINK_ISCSI socket");
		return -1;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* kernel */
	dest_addr.nl_groups = 0; /* unicast */

	log_debug(7, "created NETLINK_ISCSI socket...");

	return ctrl_fd;
}

void
ctldev_close(int ctrl_fd)
{
	close(ctrl_fd);
}



#endif



int
ctldev_writev(int ctrl_fd, iscsi_uevent_e type, struct iscsi_iovec *iovp, int count)
{
  printf("entering ctldev_writev\n");
	int i, rc;
	//struct nlmsghdr *nlh;
	//struct msghdr msg;
	struct iscsi_iovec iov;
	int datalen = 0;

	for (i = 0; i < count; i++) {
		datalen += iovp[i].iov_len;
	}

	if (xmitbuf && type != ISCSI_UEVENT_SEND_PDU) {
		for (i = 0; i < count; i++) {
			memcpy(xmitbuf + xmitlen,
			       iovp[i].iov_base, iovp[i].iov_len);
			xmitlen += iovp[i].iov_len;
		}
		return datalen;
	}

	/*
	nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(datalen));
	if (!nlh) {
		log_error("could not allocate memory for NL message");
		return -1;
	}
	nlh->nlmsg_len = NLMSG_SPACE(datalen);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;

	datalen = 0;
	for (i = 0; i < count; i++) {
		memcpy(NLMSG_DATA(nlh) + datalen, iovp[i].iov_base,
		       iovp[i].iov_len);
		datalen += iovp[i].iov_len;
	}
	iov.iov_base = (void*)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = sendmsg(ctrl_fd, &msg, 0);

	free(nlh);
	*/
	//return rc;
}

int
ksession_create(int ctrl_fd, uiscsi_session_t *session)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_SESSION;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.c_session.session_handle = (unsigned long)session;
	ev.u.c_session.initial_cmdsn = session->nrec.session.initial_cmdsn;

	//if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
	//	log_error("can't create session with id = %d (%d)",
	//		  session->id, errno);
	//	return rc;
	//}
	//printf("11\n");
	ev.r.c_session_ret.handle = kiscsi_session_create(
		       ev.u.c_session.session_handle,
		       ev.u.c_session.initial_cmdsn, &ev.r.c_session_ret.sid);

	//printf("12\n");
	if (!ev.r.c_session_ret.handle || ev.r.c_session_ret.sid < 0)
		return -EIO;

	session->handle = ev.r.c_session_ret.handle;
	session->id = ev.r.c_session_ret.sid;
	//printf("13\n");
	//log_debug(3, "created new iSCSI session, handle 0x%p", (void*)session->handle);

	return 0;
}


int
ksession_cnx_create(int ctrl_fd, uiscsi_session_t *session, uiscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.c_cnx.session_handle = session->handle;
	ev.u.c_cnx.cnx_handle = (unsigned long)conn;
	ev.u.c_cnx.cid = conn->id;

	//if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
	//	log_error("can't create cnx with id = %d (%d)",
	//		  conn->id, errno);
	//	return rc;
	//}

	ev.r.handle = kiscsi_conn_create(
			ev.u.c_cnx.session_handle,
			ev.u.c_cnx.cnx_handle,
			ev.u.c_cnx.cid);

	if (!ev.r.handle)
		return -EIO;

	conn->handle = ev.r.handle;
	printf("[ksession_cnx_create]conn->handle is %p\n", conn->handle);
	//log_debug(3, "created new iSCSI connection, handle 0x%p",
	//	  (void*)conn->handle);
	return 0;
}



int
ksession_cnx_bind(int ctrl_fd, uiscsi_session_t *session, uiscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_BIND_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.b_cnx.session_handle = session->handle;
	ev.u.b_cnx.cnx_handle = conn->handle;
	ev.u.b_cnx.transport_fd = conn->socket_fd;
	ev.u.b_cnx.is_leading = (conn->id == 0);

	//if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
	//	log_error("can't bind a cnx with id = %d (%d)",
	//		  conn->id, errno);
	//	return rc;
	//}
	ev.r.retcode = kiscsi_conn_bind(
			ev.u.b_cnx.session_handle,
			ev.u.b_cnx.cnx_handle,
			ev.u.b_cnx.transport_fd,
			ev.u.b_cnx.is_leading);
	
	if (!ev.r.retcode) 
	{
		//log_debug(3, "bound iSCSI connection (handle 0x%p) to "
		//	  "session (handle 0x%p)", (void*)conn->handle,
		//	  (void*)session->handle);
	} 
	else 
	{
		//log_error("can't bind a cnx with id = %d, retcode %d",
		//	  conn->id, ev.r.retcode);
	}
	return ev.r.retcode;
}


int ksession_recv(int ctrl_fd, uiscsi_conn_t *conn)
{		
	int rc;
	struct iscsi_uevent ev;
	memset(&ev, 0, sizeof(struct iscsi_uevent));

	printf("conn->handle address is %p\n", conn->handle);
	ev.u.b_cnx.cnx_handle = conn->handle;
	ev.r.retcode = kiscsi_tcp_recv(ev.u.b_cnx.cnx_handle);

	if (!ev.r.retcode) 
	{
		//log_debug(3, "bound iSCSI connection (handle 0x%p) to "
		//	  "session (handle 0x%p)", (void*)conn->handle,
		//	  (void*)session->handle);
	} 
	else 
	{
		//log_error("can't bind a cnx with id = %d, retcode %d",
		//	  conn->id, ev.r.retcode);
	}
	return ev.r.retcode;
}


int
ksession_send_pdu_begin(int ctrl_fd, uiscsi_session_t *session,
			uiscsi_conn_t *conn, int hdr_size, int data_size)
{
	struct iscsi_uevent *ev;

	if (xmitbuf) {
		printf("send's begin state machine bug?\n");
		return -EIO;
	}

	xmitbuf = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	if (!xmitbuf) {
		printf("can not allocate memory for xmitbuf\n");
		return -ENOMEM;
	}
	xmitlen = sizeof(*ev);
	ev = xmitbuf;
	
	memset(ev, 0, sizeof(*ev));
	ev->type = ISCSI_UEVENT_SEND_PDU;
	ev->transport_id = 0; /* FIXME: hardcoded */
	ev->u.send_pdu.cnx_handle = conn->handle;
	ev->u.send_pdu.hdr_size = hdr_size;
	ev->u.send_pdu.data_size = data_size;

	printf("send PDU began for hdr %d bytes and data %d bytes\n", hdr_size, data_size);

	return 0;
}





int
ksession_send_pdu_end(int ctrl_fd, uiscsi_session_t *session, uiscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent *ev;
	struct iscsi_iovec iov[1];

	if (!xmitbuf) {
		printf("send's end state machine bug?\n");
		return -EIO;
	}


	
	ev = xmitbuf;
	if (ev->u.send_pdu.cnx_handle != conn->handle) {
		printf ("send's end state machine corruption?\n");
		cvm_common_free_fpa_buffer(xmitbuf, CVMX_FPA_PACKET_POOL, 0);
		xmitbuf = NULL;
		return -EIO;
	}

	iov[0].iov_base = xmitbuf;
	iov[0].iov_len = xmitlen;

	//if ((rc = __ksession_call(ctrl_fd, xmitbuf, xmitlen)) < 0)
	//	goto err;
	// ISCSI_UEVENT_SEND_PDU

	ev->r.retcode = kiscsi_send_pdu(
		       ev->u.send_pdu.cnx_handle,
		       (struct iscsi_hdr*)((char*)ev + sizeof(*ev)),
		       (char*)ev + sizeof(*ev) + ev->u.send_pdu.hdr_size,
			ev->u.send_pdu.data_size);
	
	
	if (ev->r.retcode)
		goto err;
	
	if (ev->type != ISCSI_UEVENT_SEND_PDU) {
		printf("bad event?\n");
		cvm_common_free_fpa_buffer(xmitbuf, CVMX_FPA_PACKET_POOL, 0);
		xmitbuf = NULL;
		return -EIO;
	}

	printf( "send PDU finished for cnx (handle %p)\n", (void*)conn->handle);

	cvm_common_free_fpa_buffer(xmitbuf, CVMX_FPA_PACKET_POOL, 0);
	xmitbuf = NULL;
	return 0;

err:
	printf("can't finish send PDU operation for cnx with id = %d (%d), retcode %d\n",
		  conn->id, errno, ev->r.retcode);
	cvm_common_free_fpa_buffer(xmitbuf, CVMX_FPA_PACKET_POOL, 0);
	xmitbuf = NULL;
	xmitlen = 0;
	return rc;
}




int
ksession_recv_pdu_begin(int ctrl_fd, uiscsi_conn_t *conn, unsigned long recv_handle,
				unsigned long *pdu_handle, int *pdu_size)
{
	if (recvbuf) {
		//log_error("recv's begin state machine bug?");
		return -EIO;
	}
	recvbuf = (void*)recv_handle + sizeof(struct iscsi_uevent);
	recvlen = 0;
	*pdu_handle = recv_handle;

	//log_debug(3, "recv PDU began, pdu handle 0x%p", (void*)*pdu_handle);

	return 0;
}

int
ksession_recv_pdu_end(int ctrl_fd, uiscsi_conn_t *conn, unsigned long pdu_handle)
{
	if (!recvbuf) {
		//log_error("recv's end state machine bug?");
		return -EIO;
	}

	//log_debug(3, "recv PDU finished for pdu handle 0x%p", (void*)pdu_handle);

	free((void*)pdu_handle);
	recvbuf = NULL;
	return 0;
}


int
ksession_set_param(int ctrl_fd, uiscsi_conn_t *conn, iscsi_param_e param,
		   uint32_t value)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_SET_PARAM;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.set_param.cnx_handle = (unsigned long)conn->handle;
	ev.u.set_param.param = param;
	ev.u.set_param.value = value;

	ev.r.retcode = kiscsi_set_param(ev.u.set_param.cnx_handle, ev.u.set_param.param, ev.u.set_param.value);

	//if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
	//	log_error("can't set operational parameter %d for cnx with "
	//		  "id = %d (%d)", param, conn->id, errno);
	//	return rc;
	//}
	if (!ev.r.retcode) {
		printf("ksession_set_param: set operational parameter %d to %u\n", param, value);
	} 
	else {
		printf ("ksession_set_param: can't set operational parameter %d for cnx with id = %d, retcode %d\n", param, conn->id, ev.r.retcode);
	}

	return ev.r.retcode;
}






int
ksession_start_cnx(int ctrl_fd, uiscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.start_cnx.cnx_handle = conn->handle;

	/*if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't start connection 0x%p with "
			  "id = %d (%d)", (void*)conn->handle,
			  conn->id, errno);
		return rc;
	}*/

	ev.r.retcode =  kiscsi_conn_start(ev.u.start_cnx.cnx_handle);
	if (!ev.r.retcode) {
		printf( "ksession_start_cnx: connection 0x%p is operational now\n", (void*)conn->handle);
	} 
	else {
		printf ("ksession_start_cnx: can't start connection 0x%p with id = %d, retcode %d\n", (void*)conn->handle,
			  conn->id, ev.r.retcode);
	}
	return ev.r.retcode;
}


