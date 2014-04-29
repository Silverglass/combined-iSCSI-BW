/*
 * iSCSI Session Management and Slow-path Control
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
/*
#include <unistd.h>
#include <search.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "initiator.h"
#include "iscsid.h"
#include "iscsi_if.h"
#include "iscsi_ifev.h"
#include "ipc.h"
#include "idbm.h"
#include "log.h"
*/

#include <unistd.h>
#include <search.h>
#include <string.h>
#include <stdlib.h>
//#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>

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


#include "initiator.h"
//#include "iscsi_proto.h"
//#include "iscsi_tcp.h"
//#include "iscsi_if.h"
//#include "iscsi_ifev.h"

//Renjs
extern CVMX_SHARED cvmx_spinlock_t iscsilock[10];
extern CVMX_SHARED uint64_t nextlun ;
extern CVMX_SHARED uint64_t lunip[6];
extern CVMX_SHARED uint64_t run ;

#ifdef CMD
static void __session_mainloop(void *data);

static cnx_login_status_e
__login_response_status(uiscsi_conn_t *conn,
		      enum iscsi_login_status login_status)
{
	switch (login_status) {
	case LOGIN_OK:
		/* check the status class and detail */
		return CNX_LOGIN_SUCCESS;
	case LOGIN_IO_ERROR:
	case LOGIN_WRONG_PORTAL_GROUP:
	case LOGIN_REDIRECTION_FAILED:
		iscsi_disconnect(conn);
		return CNX_LOGIN_RETRY;
	default:
		iscsi_disconnect(conn);
		log_error("cnx %d giving up on login attempts", conn->id);
		break;
	}

	return CNX_LOGIN_FAILED;
}

static cnx_login_status_e
__check_iscsi_status_class(uiscsi_session_t *session, int cid,
			uint8_t status_class, uint8_t status_detail)
{
	uiscsi_conn_t *conn = &session->cnx[cid];

	switch (status_class) {
	case ISCSI_STATUS_CLS_SUCCESS:
		return CNX_LOGIN_SUCCESS;
	case ISCSI_STATUS_CLS_REDIRECT:
		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_TGT_MOVED_TEMP:
			return CNX_LOGIN_IMM_RETRY;
		case ISCSI_LOGIN_STATUS_TGT_MOVED_PERM:
			/*
			 * for a permanent redirect, we need to update the
			 * portal address within a record,  and then try again.
			 */
                        return CNX_LOGIN_IMM_REDIRECT_RETRY;
		default:
			log_error("cnx %d login rejected: redirection "
			        "type 0x%x not supported",
				conn->id, status_detail);
			iscsi_disconnect(conn);
			return CNX_LOGIN_RETRY;
		}
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		iscsi_disconnect(conn);

		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_AUTH_FAILED:
			log_error("cnx %d login rejected: Initiator "
			       "failed authentication with target", conn->id);
			if ((session->num_auth_buffers < 5) &&
			    (session->username || session->password_length ||
			    session->bidirectional_auth))
				/*
				 * retry, and hope we can allocate the auth
				 * structures next time.
				 */
				return CNX_LOGIN_RETRY;
			else
				return CNX_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_TGT_FORBIDDEN:
			log_error("cnx %d login rejected: initiator "
			       "failed authorization with target", conn->id);
			return CNX_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_TGT_NOT_FOUND:
			log_error("cnx %d login rejected: initiator "
			       "error - target not found (%02x/%02x)",
			       conn->id, status_class, status_detail);
			return CNX_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_NO_VERSION:
			/*
			 * FIXME: if we handle multiple protocol versions,
			 * before we log an error, try the other supported
			 * versions.
			 */
			log_error("cnx %d login rejected: incompatible "
			       "version (%02x/%02x), non-retryable, "
			       "giving up", conn->id, status_class,
			       status_detail);
			return CNX_LOGIN_FAILED;
		default:
			log_error("cnx %d login rejected: initiator "
			       "error (%02x/%02x), non-retryable, "
			       "giving up", conn->id, status_class,
			       status_detail);
			return CNX_LOGIN_FAILED;
		}
	case ISCSI_STATUS_CLS_TARGET_ERR:
		log_error("cnx %d login rejected: target error "
		       "(%02x/%02x)\n", conn->id, status_class, status_detail);
		iscsi_disconnect(conn);
		/*
		 * We have no idea what the problem is. But spec says initiator
		 * may retry later.
		 */
		 return CNX_LOGIN_RETRY;
	default:
		log_error("cnx %d login response with unknown status "
		       "class 0x%x, detail 0x%x\n", conn->id, status_class,
		       status_detail);
		iscsi_disconnect(conn);
		break;
	}

	return CNX_LOGIN_FAILED;
}

static void
__setup_authentication(uiscsi_session_t *session,
			struct iscsi_auth_config *auth_cfg)
{
	/* if we have any incoming credentials, we insist on authenticating
	 * the target or not logging in at all
	 */
	if (auth_cfg->username_in[0]
	    || auth_cfg->password_length_in) {
		/* sanity check the config */
		if ((auth_cfg->username[0] == '\0')
		    || (auth_cfg->password_length == 0)) {
			log_debug(1,
			       "node record has incoming "
			       "authentication credentials but has no outgoing "
			       "credentials configured, exiting");
			return;
		}
		session->bidirectional_auth = 1;
	} else {
		/* no or 1-way authentication */
		session->bidirectional_auth = 0;
	}

	/* copy in whatever credentials we have */
	strncpy(session->username, auth_cfg->username,
		sizeof (session->username));
	session->username[sizeof (session->username) - 1] = '\0';
	if ((session->password_length = auth_cfg->password_length))
		memcpy(session->password, auth_cfg->password,
		       session->password_length);

	strncpy(session->username_in, auth_cfg->username_in,
		sizeof (session->username_in));
	session->username_in[sizeof (session->username_in) - 1] = '\0';
	if ((session->password_length_in =
	     auth_cfg->password_length_in))
		memcpy(session->password_in, auth_cfg->password_in,
		       session->password_length_in);

	if (session->password_length || session->password_length_in) {
		/* setup the auth buffers */
		session->auth_buffers[0].address = &session->auth_client_block;
		session->auth_buffers[0].length =
		    sizeof (session->auth_client_block);
		session->auth_buffers[1].address =
		    &session->auth_recv_string_block;
		session->auth_buffers[1].length =
		    sizeof (session->auth_recv_string_block);

		session->auth_buffers[2].address =
		    &session->auth_send_string_block;
		session->auth_buffers[2].length =
		    sizeof (session->auth_send_string_block);

		session->auth_buffers[3].address =
		    &session->auth_recv_binary_block;
		session->auth_buffers[3].length =
		    sizeof (session->auth_recv_binary_block);

		session->auth_buffers[4].address =
		    &session->auth_send_binary_block;
		session->auth_buffers[4].length =
		    sizeof (session->auth_send_binary_block);

		session->num_auth_buffers = 5;
	} else {
		session->num_auth_buffers = 0;
	}
}
#endif





static int
__session_cnx_create(uiscsi_session_t *session, int cid)
{
	//struct hostent *hostn = NULL;
	uiscsi_conn_t *conn = &session->cnx[cid];
	cnx_rec_t *cnx = &session->nrec.cnx[cid];

	/* connection's timeouts */
	conn->id = cid;
	conn->login_timeout = cnx->timeo.login_timeout;
	conn->auth_timeout = cnx->timeo.auth_timeout;
	conn->active_timeout = cnx->timeo.active_timeout;
	conn->idle_timeout = cnx->timeo.idle_timeout;
	conn->ping_timeout = cnx->timeo.ping_timeout;


	/* operational parameters */
	conn->max_recv_dlength = cnx->iscsi.MaxRecvDataSegmentLength = 262144;
	/*
	 * iSCSI default, unless declared otherwise by the
	 * target during login
	 */
	conn->max_xmit_dlength = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;
	
	conn->hdrdgst_en = cnx->iscsi.HeaderDigest;
	conn->datadgst_en = cnx->iscsi.DataDigest;

	/* TCP options */
	conn->tcp_window_size = cnx->tcp.window_size;

	/* FIXME: type_of_service */

	/* resolve the string address to an IP address */
	//while (!hostn) 
	//{
	//	hostn = gethostbyname(cnx->address);
	//	if (hostn) 
	//	{

			/* save the resolved address */
			//conn->ip_length = hostn->h_length;

			//conn->port = cnx->port;
			// memcpy(&conn->ip_address, hostn->h_addr,  MIN(sizeof(cnx->address), hostn->h_length));
	
			//conn->port = 3260;
			//conn->ip_address = "192.168.1.101";  // ?
			

			/* FIXME: IPv6 */
			//log_debug(4, "resolved %s to %u.%u.%u.%u",
			//	 cnx->address, conn->ip_address[0],
			//	 conn->ip_address[1], conn->ip_address[2],
			//	 conn->ip_address[3]);
	//	} 
	//	else 
	//	{
			//printf("cannot resolve host name %s", cnx->address);
	//		return 1;
	//	}
	//}

	conn->state = STATE_FREE;
	conn->session = session;

	return 0;
}

void
session_cnx_destroy(uiscsi_session_t *session, int cid)
{
	/* nothing to do right now */
}

static uiscsi_session_t*
__session_create(node_rec_t *rec)
{
	uiscsi_session_t *session;

	session = cvmx_bootmem_alloc(sizeof(uiscsi_session_t)*2, CVMX_CACHE_LINE_SIZE);
	if (session == NULL) {
		//log_debug(1, "can not allocate memory for session");
		return NULL;
	}

	/* opened at daemon load time (iscsid.c) */
	//session->ctrl_fd = control_fd;

	/* save node record. we might need it for redirection */
	memcpy(&session->nrec, rec, sizeof(node_rec_t));

	/* initalize per-session queue */
	//session->queue = queue_create(4, 4, NULL, session);
	//if (session->queue == NULL) {
	//	log_error("can not create session's queue");
	//	free(session);
	//	return NULL;
	//}

	/* initalize per-session event processor */
	//actor_new(&session->mainloop, __session_mainloop, session);
	//actor_schedule(&session->mainloop);

	/* session's operational parameters */
	session->initial_r2t_en = rec->session.iscsi.InitialR2T;
	session->imm_data_en = rec->session.iscsi.ImmediateData;
	session->first_burst = rec->session.iscsi.FirstBurstLength =262144;
	session->max_burst = rec->session.iscsi.MaxBurstLength = 16776192;
	
	session->def_time2wait = rec->session.iscsi.DefaultTime2Wait = 2;
	session->def_time2retain = rec->session.iscsi.DefaultTime2Retain = 0;
	session->erl = rec->session.iscsi.ERL;
	session->portal_group_tag = rec->tpgt;
	
	session->type = ISCSI_SESSION_TYPE_NORMAL;


	//session->initiator_name = dconfig->initiator_name;
	//session->initiator_alias = dconfig->initiator_alias;
	//session->initiator_name = "iqn.2002-10.com.infortrend:raid.sn7905538.308";
	//Renjs
		//Renjs
    
	switch(nextlun)
	{
		case 0:
			strcpy(session->target_name, "iqn.2010-07.com.bwstor:none.dg1.vd1");  // BWS
			break;
		case 1:
			strcpy(session->target_name, "iqn.2010-07.com.bwstor:none.dg2.vd2");  // BWS
			break;
		case 2:
			strcpy(session->target_name, "iqn.2010-07.com.bwstor:none.dg3.vd3");  // BWS
			break;
		case 3:
			strcpy(session->target_name, "iqn.2010-07.com.bwstor:none.dg4.vd4");  // BWS
			break;
		case 4:
			strcpy(session->target_name, "iqn.2010-07.com.bwstor:none.dg5.vd5");  // BWS
			break;
		case 5:
			strcpy(session->target_name, "iqn.2010-07.com.bwstor:none.dg6.vd6");  // BWS
			break;
		default:break;	
			
	}
  
  //strcpy(session->target_name, "iqn.2012-07.com.Sugon:alias.tgt0000.4e57565501000020");
	session->initiator_name = "iqn.2002-10.com.infortrend:raid.sn7905538.409";
	//session->initiator_alias = "temp.init.alias";
	session->initiator_alias = "(None)";
	//strcpy(session->target_name, "iqn.2010-07.com.bwstor:none.dg1.vd1");  // BWS

	//strcpy(session->target_name, "iqn.2002-10.com.infortrend:raid.sn7905538.001"); //Dawn
	//strncpy(session->target_name, rec->name, TARGET_NAME_MAXLEN);
	
	session->vendor_specific_keys = 1;

	/* session's misc parameters */
	session->reopen_cnt = rec->session.reopen_max;

	/* OUI and uniqifying number */
	session->isid[0] = 0x00;
	session->isid[1] = 0x02;
	session->isid[2] = 0x3D;
	session->isid[3] = 0;
	session->isid[4] = 0;
	session->isid[5] = 0;

	/* setup authentication variables for the session*/
	//__setup_authentication(session, &rec->session.auth);

	//insque(&session->item, &provider[0].sessions);

	return session;
}




#ifdef CMD
static void
__session_destroy(uiscsi_session_t *session)
{
	remque(&session->item);
	queue_flush(session->queue);
	queue_destroy(session->queue);
	actor_delete(&session->mainloop);
	free(session);
}

static void
__session_ipc_login_cleanup(queue_task_t *qtask, ipc_err_e err)
{
	uiscsi_conn_t *conn = qtask->conn;
	uiscsi_session_t *session = conn->session;

	qtask->u.login.rsp.err = err;
	write(qtask->u.login.ipc_fd, &qtask->u.login.rsp,
		sizeof(qtask->u.login.rsp));
	close(qtask->u.login.ipc_fd);
	free(qtask);
	if (conn->login_context.buffer)
		free(conn->login_context.buffer);
	session_cnx_destroy(session, conn->id);
	if (conn->id == 0)
		__session_destroy(session);
}




static void
__send_pdu_timedout(void *data)
{
	queue_task_t *qtask = data;
	uiscsi_conn_t *conn = qtask->conn;
	uiscsi_session_t *session = conn->session;

	if (conn->send_pdu_in_progress) {
		queue_produce(session->queue, EV_CNX_TIMER, qtask, 0, 0);
		actor_schedule(&session->mainloop);
	}
}

static void
__send_pdu_timer_add(struct iscsi_conn *conn, int timeout)
{
	if (conn->state == STATE_IN_LOGIN) {
		iscsi_login_context_t *c = &conn->login_context;
		conn->send_pdu_in_progress = 1;
		actor_timer(&conn->send_pdu_timer, timeout*1000,
			    __send_pdu_timedout, c->qtask);
		log_debug(7, "send_pdu timer added %d secs", timeout);
	}
}

static void
__send_pdu_timer_remove(struct iscsi_conn *conn)
{
	if (conn->send_pdu_in_progress) {
		actor_delete(&conn->send_pdu_timer);
		conn->send_pdu_in_progress = 0;
		log_debug(7, "send_pdu timer removed");
	}
}

#endif



//Renjs
int
__send_nopin_rsp(uiscsi_conn_t *conn, struct iscsi_nopin *rhdr, char *data)
{
	printf("call __send_nopin_rsp!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	struct iscsi_nopout hdr;

	memset(&hdr, 0, sizeof(struct iscsi_nopout));
	hdr.opcode = ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	hdr.flags = ISCSI_FLAG_CMD_FINAL;
	hdr.dlength[0] = rhdr->dlength[0];
	hdr.dlength[1] = rhdr->dlength[1];
	hdr.dlength[2] = rhdr->dlength[2];
	memcpy(hdr.lun, rhdr->lun, 8);
	hdr.ttt = rhdr->ttt;
	hdr.itt = ISCSI_RESERVED_TAG;

	return iscsi_send_pdu(conn, (struct iscsi_hdr*)&hdr,
	       ISCSI_DIGEST_NONE, data, ISCSI_DIGEST_NONE, 0);
}






// ³É¹¦·µ»Ø1£¬Ê§°Ü·µ»Ø0
//static void __session_cnx_recv_pdu(queue_item_t *item)
int  __session_cnx_recv_pdu(iscsi_cnx_h cp_cnx, struct iscsi_hdr *hdr, char *data, uint32_t data_size)
{
	printf("__session_cnx_recv_pdu: entering __session_cnx_recv_pdu!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	uiscsi_conn_t* conn= (uiscsi_conn_t*)iscsi_ptr(cp_cnx);
	// uiscsi_conn_t *conn = item->context;

	uiscsi_session_t *session = conn->session;

	// conn->recv_handle = *(ulong_t*)queue_item_data(item);

	if (conn->state == STATE_IN_LOGIN) 
	{
		iscsi_login_context_t *c = &conn->login_context;

		if (iscsi_login_rsp(session, c, hdr, data, data_size)) 
		{
			//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
			return 0;
		}
		printf("__session_cnx_recv_pdu: conn->current_stage = %d\n", conn->current_stage);
		
		if (conn->current_stage != ISCSI_FULL_FEATURE_PHASE) 
		{
			// ²»¿ÉÄÜ½øÀ´
			/* more nego. needed! */
			printf("iscsi_login_req again !!!!!!!!!!!!!!!!!!!!!!!!!!\n ");
			conn->state = STATE_IN_LOGIN;
			if (iscsi_login_req(session, c)) 
			{
				//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
				return 0;
			}
		} 
		else // ISCSI_FULL_FEATURE_PHASE
		{
			/* almost! entered full-feature phase */

			//if (__login_response_status(conn, c->ret) != CNX_LOGIN_SUCCESS) 
			//{
			//	__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
			//	return;
			//}

			/* check the login status */
			//if (__check_iscsi_status_class(session, conn->id, c->status_class, c->status_detail) !=CNX_LOGIN_SUCCESS) 
			//{
			//	__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
			//	return;
			//}

			/* Entered full-feature phase! */
			printf("__session_cnx_recv_pdu: set_param ... \n");
			if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_MAX_RECV_DLENGTH, conn->max_recv_dlength)) 
			{	
				printf("1\n");
				//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
				return 0;
			}
			if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_MAX_XMIT_DLENGTH, conn->max_xmit_dlength)) 
			{
				printf("2\n");
				//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
				return 0;
			}
			if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_HDRDGST_EN, conn->hdrdgst_en)) 
			{
				printf("3\n");
				//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
				return 0;
			}
			if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_DATADGST_EN, conn->datadgst_en)) 
			{
				//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
				return 0;
			}
			if (conn->id == 0) 
			{
				/* setup session's op. parameters just once */
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_INITIAL_R2T_EN, session->initial_r2t_en)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_MAX_R2T,1 /* FIXME: session->max_r2t */)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_IMM_DATA_EN, session->imm_data_en)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_FIRST_BURST, session->first_burst)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_MAX_BURST, session->max_burst)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_PDU_INORDER_EN, session->pdu_inorder_en)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_DATASEQ_INORDER_EN, session->dataseq_inorder_en)) 
				{
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_ERL, 0 /* FIXME: session->erl */)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_IFMARKER_EN, 0 /* FIXME: session->ifmarker_en */)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				if (ksession_set_param(session->ctrl_fd, conn, ISCSI_PARAM_OFMARKER_EN, 0 /* FIXME: session->ofmarker_en */)) 
				{
					//__session_ipc_login_cleanup(c->qtask, IPC_ERR_LOGIN_FAILURE);
					return 0;
				}
				printf("11111111111111111111111111111111\n");
				/*
				 * FIXME: set these timeouts via set_param() API
				 *
				 * rec->session.timeo
				 * rec->session.timeo
				 * rec->session.err_timeo
				 */
			}
			printf("22222222222222222222222222222222\n");
			//if (ksession_start_cnx(session->ctrl_fd, conn)) 
			//{
				//__session_ipc_login_cleanup(c->qtask, IPC_ERR_INTERNAL);
			//	return  0;
			//}
			//printf("__session_cnx_recv_pdu: ksession_start_cnx done! \n");
			
			//conn->state = STATE_LOGGED_IN;
			printf("333333333333333333333333333333333\n");
			//c->qtask->u.login.rsp.err = IPC_OK;
			
			//write(c->qtask->u.login.ipc_fd, &c->qtask->u.login.rsp,
			//	sizeof(c->qtask->u.login.rsp));
			//close(c->qtask->u.login.ipc_fd);
			//free(c->qtask);
		printf("4444444444444444444444444444444444\n");
		}// ISCSI_FULL_FEATURE_PHASE
		printf("5555555555555555555555555555555555\n");
	} 

	else if (conn->state == STATE_LOGGED_IN) {

		printf("__session_cnx_recv_pdu:  conn->state == STATE_LOGGED_IN! \n");
		struct iscsi_hdr hdr;

		/* read incomming PDU */
		if (!iscsi_recv_pdu(conn, &hdr, ISCSI_DIGEST_NONE, conn->data, data_size,
			    DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
			    ISCSI_DIGEST_NONE, 0)) 
		{
			return 0;
		}

		if (hdr.opcode == ISCSI_OP_NOOP_IN) {
			if (!__send_nopin_rsp(conn,
				     (struct iscsi_nopin*)&hdr, conn->data)) 
			{
				printf("can not send nopin response\n");
			}
		} else {
			printf ("unsupported opcode 0x%x\n", hdr.opcode);
		}
	}
	printf("__session_cnx_recv_pdu:  the end ! \n");
	return 1;
}







//static void __session_cnx_poll(queue_item_t *item)
static void __session_cnx_poll(uiscsi_session_t *session, uiscsi_conn_t *conn)
{
	ipc_err_e err = IPC_OK;
	//queue_task_t *qtask = item->context;
	//uiscsi_conn_t *conn = qtask->conn;
	iscsi_login_context_t *c = &conn->login_context;
	//uiscsi_session_t *session = conn->session;
	int rc;
	//uint32_t initial_cmdsn = 0;

	if (conn->state == STATE_XPT_WAIT) 
	{
		//rc = iscsi_tcp_poll(conn);
		//if (rc == 0) {
			/* timedout: poll again */
		//	queue_produce(session->queue, EV_CNX_POLL, qtask, 0, 0);
		//	actor_schedule(&session->mainloop);
		//} 
		
		//else if (rc > 0) 
		//{

			/* connected! */

			memset(c, 0, sizeof(iscsi_login_context_t));

			//actor_delete(&conn->connect_timer);
			//printf("1\n");
			if (conn->id == 0 && ksession_create(session->ctrl_fd, session)) 
			{
				err = IPC_ERR_INTERNAL;
				goto cleanup;
			}
			//printf("2\n");
			if (ksession_cnx_create(session->ctrl_fd, session, conn)) 
			{
				err = IPC_ERR_INTERNAL;
				goto s_cleanup;
			}
			//printf("3\n");
			if (ksession_cnx_bind(session->ctrl_fd, session, conn)) 
			{
				err = IPC_ERR_INTERNAL;
				goto c_cleanup;
			}
			//printf("4\n");
			conn->kernel_io = 1;

			//conn->send_pdu_begin = ksession_send_pdu_begin;
			//conn->send_pdu_end = ksession_send_pdu_end;
			//conn->recv_pdu_begin = ksession_recv_pdu_begin;
			//conn->recv_pdu_end = ksession_recv_pdu_end;
			//conn->send_pdu_timer_add = __send_pdu_timer_add;
			//conn->send_pdu_timer_remove = __send_pdu_timer_remove;

			//c->qtask = qtask;
			
			c->cid = conn->id;
			c->buffer = cvmx_bootmem_alloc(DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH, CVMX_CACHE_LINE_SIZE);
			if (!c->buffer) {
				//log_error("failed to aallocate recv data buffer\n");
				printf("failed to allocate recv data buffer\n");
				err = IPC_ERR_NOMEM;
				goto c_cleanup;
			}
			c->bufsize = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;
			//printf("5\n");
			if (iscsi_login_begin(session, c)) 
			{
				err = IPC_ERR_LOGIN_FAILURE;
				goto mem_cleanup;
			}
			printf("6\n");
			printf("[__session_cnx_poll]conn->handle is %p\n", conn->handle);	
			conn->state = STATE_IN_LOGIN;
			if (iscsi_login_req(session, c)) 
			{
				err = IPC_ERR_LOGIN_FAILURE;
				goto mem_cleanup;
			}
			printf("7\n");
		//} 

		//else 
		//{
		//	actor_delete(&conn->connect_timer);
			/* error during connect */
		//	err = IPC_ERR_TCP_FAILURE;
		//	goto cleanup;
		//}
	}

	return;

mem_cleanup:
	free(c->buffer);
	c->buffer = NULL;
c_cleanup:
	//if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
	//	log_error("can not safely destroy connection %d", conn->id);
	//}
s_cleanup:
	//if (ksession_destroy(session->ctrl_fd, session)) {
	//	log_error("can not safely destroy session %d", session->id);
	//}
cleanup:
	//__session_ipc_login_cleanup(qtask, err);
	return;
}



#ifdef CMD

static void
__session_cnx_timer(queue_item_t *item)
{
	queue_task_t *qtask = item->context;
	uiscsi_conn_t *conn = qtask->conn;
	uiscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		log_debug(6, "cnx_timer popped at XPT_WAIT ");
		/* timeout during connect. clean connection. write rsp */
		__session_ipc_login_cleanup(qtask, IPC_ERR_TCP_TIMEOUT);
	} else if (conn->state == STATE_IN_LOGIN) {
		log_debug(6, "cnx_timer popped at IN_LOGIN");
		/* send pdu timeout. clean connection. write rsp */
		if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
			log_error("can not safely destroy connection %d",
				  conn->id);
		}
		if (ksession_destroy(session->ctrl_fd, session)) {
			log_error("can not safely destroy session %d",
				  session->id);
		}
		__session_ipc_login_cleanup(qtask, IPC_ERR_PDU_TIMEOUT);
	}
}

#define R_STAGE_NO_CHANGE	0
#define R_STAGE_SESSION_CLEANUP	1
#define R_STAGE_SESSION_REOPEN	2

static void
__session_cnx_error(queue_item_t *item)
{
	iscsi_err_e error = *(iscsi_err_e *)queue_item_data(item);
	uiscsi_conn_t *conn = item->context;
	uiscsi_session_t *session = conn->session;
	int r_stage = R_STAGE_NO_CHANGE;

	log_warning("detected iSCSI connection (handle %p) error (%d)",
			(void*)conn->handle, error);

	if (conn->state == STATE_LOGGED_IN) {
		int i;

		/* mark failed connection */
		conn->state = STATE_CLEANUP_WAIT;

		if (session->erl > 0) {
			/* check if we still have some logged in connections */
			for (i=0; i<ISCSI_CNX_MAX; i++) {
				if (session->cnx[i].state == STATE_LOGGED_IN) {
					break;
				}
			}
			if (i != ISCSI_CNX_MAX) {
				/* FIXME: re-assign leading connection
				 *        for ERL>0 */
			}
		} else {
			/* mark all connections as failed */
			for (i=0; i<ISCSI_CNX_MAX; i++) {
				if (session->cnx[i].state == STATE_LOGGED_IN) {
					session->cnx[i].state =
						STATE_CLEANUP_WAIT;
				}
			}
			if (--session->reopen_cnt > 0)
				r_stage = R_STAGE_SESSION_REOPEN;
			else
				r_stage = R_STAGE_SESSION_CLEANUP;
		}
	} else if (conn->state == STATE_IN_LOGIN) {
		log_debug(1, "ignoring cnx error in login. let it timeout");
		return;
	}

	if (r_stage == R_STAGE_SESSION_REOPEN) {
		log_debug(1, "re-opening session %d", session->id);
#if 0
		if (ksession_stop_cnx(session->ctrl_fd, conn)) {
			log_error("can not safely stop connection %d",
				  conn->id);
			return;
		}

		iscsi_disconnect(conn);
#endif

		return;
	}

	if (ksession_stop_cnx(session->ctrl_fd, conn)) {
		log_error("can not safely stop connection %d", conn->id);
		return;
	}

	iscsi_disconnect(conn);

	if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
		log_error("can not safely destroy connection %d", conn->id);
		return;
	}
	session_cnx_destroy(session, conn->id);

	if (ksession_destroy(session->ctrl_fd, session)) {
		log_error("can not safely destroy session %d", session->id);
		return;
	}
	__session_destroy(session);
}

static void
__session_mainloop(void *data)
{
	uiscsi_session_t *session = data;
	unsigned char item_buf[sizeof(queue_item_t) + EVENT_PAYLOAD_MAX];
	queue_item_t *item = (queue_item_t *)(void *)item_buf;

	if (queue_consume(session->queue, EVENT_PAYLOAD_MAX, item) != QUEUE_IS_EMPTY) 
	{
		switch (item->event_type) 
		{
		case EV_CNX_RECV_PDU: __session_cnx_recv_pdu(item); break;
		case EV_CNX_POLL: __session_cnx_poll(item); break;
		case EV_CNX_TIMER: __session_cnx_timer(item); break;
		case EV_CNX_ERROR: __session_cnx_error(item); break;
		default:
			break;
		}
	}
}

static void
__connect_timedout(void *data)
{
	queue_task_t *qtask = data;
	uiscsi_conn_t *conn = qtask->conn;
	uiscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		queue_produce(session->queue, EV_CNX_TIMER, qtask, 0, 0);
		actor_schedule(&session->mainloop);
	}
}

uiscsi_session_t*
session_find_by_rec(node_rec_t *rec)
{
	uiscsi_session_t *session;
	struct qelem *item;

	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		session = (uiscsi_session_t *)item;
		log_debug(6, "looking for session with rec_id [%06x]...",
			  session->nrec.id);
		if (rec->id == session->nrec.id) {
			return session;
		}
		item = item->q_forw;
	}

	return NULL;
}
#endif



int session_login_task(node_rec_t *rec, iSCSI_context * context)
{
	int rc;
	uiscsi_session_t *session;
	uiscsi_conn_t *conn;
	 

	// Ö±½Ó¸³Öµ
	char ip_address[16];
	char default_port[12];
	int ip_length = 4;
	unsigned short port = 3260;

	ip_address[0] = 192;
	ip_address[1] = 168;
	ip_address[2] = 1;
  //Renjs
	ip_address[3] = lunip[nextlun];
  context->lun = nextlun;
	context->ip = ip_address[3];
	printf("session_login_task :   ip =%d \n ",lunip[nextlun]);


	//if (!rec->active_cnx)
	//	return IPC_ERR_INVAL;


	session = __session_create(rec);
	if (session == NULL) 
	{
		return IPC_ERR_LOGIN_FAILURE;
	}

	/* FIXME: login all connections! marked as "automatic" */


	session->cnx[0].port = port;
	session->cnx[0].ip_length = ip_length;
	memcpy(session->cnx[0].ip_address, ip_address, MIN(sizeof (session->cnx[0].ip_address), ip_length));
	
	

	/* create leading connection */
	if (__session_cnx_create(session, 0)) 
	{
		//__session_destroy(session);
		return IPC_ERR_LOGIN_FAILURE;
	}

	conn = &session->cnx[0];	
	printf("[session_login_task]conn->handle is %p\n", conn->handle);
	//qtask->conn = conn;

	rc = iscsi_tcp_connect(conn, 1, context);
	//if (rc < 0 && errno != EINPROGRESS) 
	if (rc < 0)
	{
		printf("[iSCSI SYSTEM]Socket connect error!\n");
		return IPC_ERR_TCP_FAILURE;
	}
	conn->state = STATE_XPT_WAIT;


	printf("set session %p,		conn %p,	context %p\n", session, conn, context);
	session->context = (uint64_t) context;
	context->session = session;
	context->conn = conn;
	context->socket_fd = conn->socket_fd;
	context->state = iSCSI_START_CONNECT;

	return 0;
}
	







int session_login_send_login_pdu(iSCSI_context * context)
{
	uiscsi_session_t *session = context->session;
	uiscsi_conn_t *conn = context->conn;
	//printf("get session %p,		conn %p\n", session, conn);
	__session_cnx_poll(session, conn);
	//printf("000000000000000000	%p\n", conn->handle);
	return 0;
}



int session_login_send_login_cmd(iSCSI_context * context)
{
	uiscsi_session_t *session = context->session;
	uiscsi_conn_t *conn = context->conn;	
	printf("[session_login_send_login_cmd]get session %p,         conn %p	conn->handle %p\n", session, conn, conn->handle);
	printf("[session_login_send_login_cmd]context is %p\n", session->context);
	printf("[session_login_send_login_cmd]iscsi session is %p\n", session->handle);
	printf("[session_login_send_login_cmd]iscsi conn is %p\n", conn->handle);
	if (!ksession_recv(session->ctrl_fd, conn)) 
	{
		//__session_ipc_login_cleanup(c->qtask, IPC_ERR_INTERNAL);
			return  12;
	}

	printf("session_login_task: recv done! \n");
	
	if (ksession_start_cnx(session->ctrl_fd, conn)) 
	{
		//__session_ipc_login_cleanup(c->qtask, IPC_ERR_INTERNAL);
			return  13;
	}
	conn->state = STATE_LOGGED_IN;
	//Renjs
	printf("session_login_task: login succeed !!! ip: 192.168.1.%d nextlun is %d  \n", context->ip,nextlun);
	//nextlun++;
	return IPC_OK;
}



int iSCSI_Login()
{
	int ret, res;
	node_rec_t * rec;
	rec = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	if(sizeof(node_rec_t) > CVMX_FPA_PACKET_POOL_SIZE)
		printf("CVMX_FPA_PACKET_POOL_SIZE is smaller than node_rec_t!\n");

	//¿¿¿¿¿context¿¿¿session¿¿¿¿¿¿¿context
	iSCSI_context * context;	
	context = (iSCSI_context *) cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	if (context == NULL)
	{
		printf("Failed to allocate context for task\n");
		return -1;
	}
	memset(context, 0, CVMX_FPA_PACKET_POOL_SIZE);
	context->context_type = CONTEXT_TYPE_ISCSI_SYSTEM; //iSCSI¿¿¿¿¿¿¿

	cvmx_wqe_t * work = (cvmx_wqe_t *) cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
	if(work == NULL)
	{
		printf("Failed to allocate shared work\n");
                return -1;
	}
        memset(work, 0, sizeof(cvmx_wqe_t));
	cvmx_spinlock_init(&context->lock);
	//context->lock = cvmx_ptr_to_phys(work);
	//printf("context lock address is %llX\n", context->lock);
	
	context->itt_used = 0;

	//iSCSI¿¿¿Login¿¿
	ret = session_login_task(rec, context); 
	printf("inic_app_loop: session_login_task ret = %d\n", ret);	
	if(ret == 0)
		printf("[iSCSI SYSTEM]iSCSI Login is Starting!\n");
	cvm_common_free_fpa_buffer(rec, CVMX_FPA_PACKET_POOL, 0);
	return ret;
}




#ifdef CMD
int
session_logout_task(uiscsi_session_t *session, queue_task_t *qtask)
{
	uiscsi_conn_t *conn;

	/* FIXME: logout all active connections */
	conn = &session->cnx[0];
	if (conn->state != STATE_LOGGED_IN &&
	    conn->state != STATE_CLEANUP_WAIT) {
		return IPC_ERR_INTERNAL;
	}

	/* FIXME: implement Logout Request */

	/* stop if connection is logged in */
	if (conn->state == STATE_LOGGED_IN &&
	    ksession_stop_cnx(session->ctrl_fd, conn)) {
		return IPC_ERR_INTERNAL;
	}

	iscsi_disconnect(conn);

	if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
		return IPC_ERR_INTERNAL;
	}
	session_cnx_destroy(session, conn->id);

	if (ksession_destroy(session->ctrl_fd, session)) {
		return IPC_ERR_INTERNAL;
	}
	__session_destroy(session);

	qtask->u.login.rsp.err = IPC_OK;
	write(qtask->u.login.ipc_fd, &qtask->u.login.rsp,
		sizeof(qtask->u.login.rsp));
	close(qtask->u.login.ipc_fd);
	free(qtask);

	return IPC_OK;
}
#endif
