/*
 * iSCSI I/O Library
 *
 * Copyright (C) 2002 Cisco Systems, Inc.
 * maintained by linux-iscsi-devel@lists.sourceforge.net
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
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>

#include <string.h>
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

#include "iSCSI-typedefs.h"

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#endif
#include "socket.h"
#include "socketvar.h"

#include "cvm-tcp-var.h"

#include "cvm-socket.h"

#include "iscsi_proto.h"
#include "initiator.h"
//#include "log.h"

extern CVMX_SHARED uint64_t nextlun;

//#define LOG_CONN_CLOSED(conn) \
//	log_error("Connection to Discovery Address %u.%u.%u.%u closed", conn->ip_address[0], conn->ip_address[1], conn->ip_address[2], conn->ip_address[3])
//#define LOG_CONN_FAIL(conn) \
//	log_error("Connection to Discovery Address %u.%u.%u.%u failed", conn->ip_address[0], conn->ip_address[1], conn->ip_address[2], conn->ip_address[3])

static int timedout;








static void
sigalarm_handler(int unused)
{
	timedout = 1;
}

/*
static void
set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);

	if (res != -1) {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			log_warning("unable to set fd flags (%s)!",
				    strerror(errno));
	} else
		log_warning("unable to get fd flags (%s)!", strerror(errno));

}
*/
void
set_non_blocking(int fd)
{
	int res = cvm_so_fcntl(fd, F_GETFL);

	if (res != -1) {
		res = cvm_so_fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			printf("unable to set fd flags !");
	} else
		printf("unable to get fd flags!");
}

	int
iscsi_writev(int ctrl_fd, int type, struct iscsi_iovec *iovp, int count)
{

	struct cvm_so_iovec_desc vector[10];
	int i;

	for(i=0; i<count; i++)
	{
		vector[i].iov_base = (uint64_t)(iovp[i].iov_base);
		vector[i].iov_len = iovp[i].iov_len;
	}

	return cvm_so_writev(ctrl_fd, vector, count);
}


	int
iscsi_read(int ctrl_fd, char *data, int count)
{
	return cvm_so_read(ctrl_fd, data, count);
}

int
iscsi_tcp_connect(uiscsi_conn_t *conn, int non_blocking, iSCSI_context * context)
{
	int rc, ret, onearg;
  printf("iscsi_tcp_connect   entering!\n");
	/* create a socket */
	//conn->socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	conn->socket_fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
	if (conn->socket_fd < 0) {
		printf("cannot create TCP socket");
		return -1;
	}

    cvm_so_fcntl(conn->socket_fd, FNONBIO, 1);

	onearg = 1;	
	rc = cvm_so_setsockopt(conn->socket_fd, CVM_IP_IPPROTO_TCP, CVM_TCP_TCP_NODELAY, &onearg, sizeof (onearg));
	if (rc < 0) {
		printf("cannot set TCP_NODELAY option on socket\n");
		cvm_so_close(conn->socket_fd);
		conn->socket_fd = -1;
		return rc;
	}	

	
	/* optionally set the window sizes */
	if (conn->tcp_window_size) {
		int window_size = conn->tcp_window_size;
		unsigned int arglen = sizeof (window_size);
	
		if (cvm_so_setsockopt(conn->socket_fd, CVM_SO_SOL_SOCKET, CVM_SO_SO_RCVBUF, (char *) &window_size, sizeof (window_size)) < 0)
		{
			printf("failed to set TCP recv window size to %u\n", window_size);
		} 
		else 
		{
			if (cvm_so_getsockopt(conn->socket_fd, CVM_SO_SOL_SOCKET, CVM_SO_SO_RCVBUF, (char *) &window_size, &arglen) >= 0) 
				printf("set TCP recv window size to %u, actually got %u\n", conn->tcp_window_size, window_size);
		}
	
		window_size = conn->tcp_window_size;
		arglen = sizeof (window_size);
	
		if (cvm_so_setsockopt(conn->socket_fd, CVM_SO_SOL_SOCKET, CVM_SO_SO_SNDBUF, (char *) &window_size, sizeof (window_size)) < 0)
		{
			printf("failed to set TCP send window size to %u\n", window_size);
		}
		else 
		{
			if (cvm_so_getsockopt(conn->socket_fd, CVM_SO_SOL_SOCKET, CVM_SO_SO_SNDBUF, (char *) &window_size, &arglen) >= 0) 
					printf("set TCP send window size to %u, actually got %u\n", conn->tcp_window_size, window_size);	
		}
	}


	/*
	 * Build a TCP connection to the target
	 */
	memset(&conn->addr, 0, sizeof (conn->addr));
	conn->addr.sin_family = CVM_SO_AF_INET;
	conn->addr.sin_port = conn->port;
	
	memcpy(&conn->addr.sin_addr.s_addr, conn->ip_address, MIN(sizeof (conn->addr.sin_addr.s_addr), conn->ip_length));

	// blocking
	//if (non_blocking)
	//	set_non_blocking(conn->socket_fd);

	printf("socket register context address is %llX\n", context);
	if ((rc = cvm_so_activate_notification (conn->socket_fd, context)) != 0) {
        CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "unable to activate notification on listen socket\n");
        cvm_so_close (conn->socket_fd);
		conn->socket_fd = -1;
        return rc;
    }

	struct cvm_ip_sockaddr_in laddr;

	laddr.sin_family = CVM_SO_AF_INET;
	laddr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
	//Renjs
	
	laddr.sin_port = cvm_common_htons(44855 + (rand() % 10000) );
	laddr.sin_len = sizeof(laddr);

	int error = cvm_so_bind(conn->socket_fd, (struct cvm_so_sockaddr*)&laddr, sizeof(struct cvm_so_sockaddr));
	if (error)
	{
		printf("DNI client application : unable to bind new socket [fd = %d, error = 0x%X]\n", conn->socket_fd, errno);
		cvm_so_close(conn->socket_fd);
		return (1);
	}
	


	cvm_so_connect(conn->socket_fd, (struct cvm_so_sockaddr*)&conn->addr, sizeof (struct cvm_so_sockaddr));

	printf("[iSCSI SYSTEM]iSCSI is starting connecting, and socket fd is %d\n", conn->socket_fd);

	
	return 0;
}


/*
int
iscsi_tcp_poll(uiscsi_conn_t *conn)
{
	int rc;
	struct pollfd pdesc;

	pdesc.fd = conn->socket_fd;
	pdesc.events = POLLOUT;
	rc = poll(&pdesc, 1, 1);
	if (rc < 0) {
		log_error("cannot make connection to %s:%d (%d)",
			 inet_ntoa(conn->addr.sin_addr), conn->port, errno);
		close(conn->socket_fd);
		conn->socket_fd = -1;
	} else if (rc > 0 && log_level > 0) {
		struct sockaddr_in local;
		socklen_t len = sizeof (local);

		if (getsockname(conn->socket_fd, (struct sockaddr *) &local,
				&len) >= 0) {
			log_debug(1, "connected local port %d to %s:%d",
				 ntohs(local.sin_port),
				 inet_ntoa(conn->addr.sin_addr), conn->port);
		}
	}
	return rc;
}
*/



#ifdef CMD
int
iscsi_connect(uiscsi_conn_t *conn)
{
	int rc, ret;
	struct sigaction action;
	struct sigaction old;

	/* set a timeout, since the socket calls may take a long time to
	 * timeout on their own
	 */
	memset(&action, 0, sizeof (struct sigaction));
	memset(&old, 0, sizeof (struct sigaction));
	action.sa_sigaction = NULL;
	action.sa_flags = 0;
	action.sa_handler = sigalarm_handler;
	sigaction(SIGALRM, &action, &old);
	timedout = 0;
	alarm(conn->login_timeout);

	/* perform blocking TCP connect operation when no async request
	 * associated. SendTargets Discovery know to work in such a mode.
	 */
	rc = iscsi_tcp_connect(conn, 0);
	if (timedout) {
		log_debug(1, "socket %d connect timed out", conn->socket_fd);
		ret = 0;
		goto done;
	} else if (rc < 0) {
		log_error("cannot make connection to %s:%d (%d)",
			 inet_ntoa(conn->addr.sin_addr), conn->port, errno);
		close(conn->socket_fd);
		ret = 0;
		goto done;
	} else if (log_level > 0) {
		struct sockaddr_in local;
		socklen_t len = sizeof (local);

		if (getsockname(conn->socket_fd, (struct sockaddr *) &local,
				&len) >= 0) {
			log_debug(1, "connected local port %d to %s:%d",
				 ntohs(local.sin_port),
				 inet_ntoa(conn->addr.sin_addr), conn->port);
		}
	}

	ret = 1;

done:
	alarm(0);
	sigaction(SIGALRM, &old, NULL);
	return ret;
}




void
iscsi_disconnect(uiscsi_conn_t *conn)
{
	if (conn->socket_fd >= 0) {
		log_debug(1, "disconnecting conn %p, fd %d", conn,
			 conn->socket_fd);
		close(conn->socket_fd);
		conn->socket_fd = -1;
	}
}


#endif













static void
iscsi_log_text(struct iscsi_hdr *pdu, char *data)
{
	int dlength = ntoh24(pdu->dlength);
	char *text = data;
	char *end = text + dlength;

	while (text && (text < end)) {
		//log_debug(4, ">    %s", text);
		text += strlen(text);
		while ((text < end) && (*text == '\0'))
			text++;
	}
}

int
iscsi_send_pdu(uiscsi_conn_t *conn, struct iscsi_hdr *hdr,
	       int hdr_digest, char *data, int data_digest, int timeout)
{
	int rc, ret = 0;
	char *header = (char *) hdr;
	char *end;
	char pad[4];
	
	struct iscsi_iovec vec[3];
	int pad_bytes;
	int pdu_length = sizeof (*hdr) + hdr->hlength + ntoh24(hdr->dlength);
	printf("pdu_length = %d, ntoh24(hdr->dlength)= %d, hdr->dlength[0]=%d, hdr->dlength[1]=%d, hdr->dlength[2]=%d\n", 
		pdu_length, ntoh24(hdr->dlength), hdr->dlength[0], hdr->dlength[1], hdr->dlength[2]);
	printf("iscsi_send_pdu: hdr->itt = 0x%x \n", hdr->itt);
	
	int remaining;
	//struct sigaction action;
	//struct sigaction old;
	uiscsi_session_t *session = conn->session;

	/* set a timeout, since the socket calls may take a long time
	 * to timeout on their own
	 */
	//if (!conn->kernel_io) {
	//	memset(&action, 0, sizeof (struct sigaction));
	//	memset(&old, 0, sizeof (struct sigaction));
	//	action.sa_sigaction = NULL;
	//	action.sa_flags = 0;
	//	action.sa_handler = sigalarm_handler;
	//	sigaction(SIGALRM, &action, &old);
	//	timedout = 0;
	//	alarm(timeout);
	//}

	memset(&pad, 0, sizeof (pad));
	memset(&vec, 0, sizeof (vec));

	//if (log_level > 0) {
	switch (hdr->opcode & ISCSI_OPCODE_MASK) 
	{
		case ISCSI_OP_LOGIN:
		{
				struct iscsi_login *login_hdr = (struct iscsi_login *) hdr;
				iscsi_log_text(hdr, data);
				break;
		}
		case ISCSI_OP_TEXT:
		{
				struct iscsi_text *text_hdr = (struct iscsi_text *) hdr;
				iscsi_log_text(hdr, data);
				break;
		}
		case ISCSI_OP_NOOP_OUT:
		{   
            //Renjs
            printf("case ISCSI_OP_NOOP_OUT:\n");
            struct iscsi_nopout *nopout_hdr = (struct iscsi_nopout *) hdr;
            iscsi_log_text(hdr, data);
            break;
    }
    default:
    break;
  }
  //}
  //Renjs
  printf("after case ISCSI_OP_NOOP_OUT:\n");
  /* send the PDU header */
  header = (char *) hdr;
  end = header + sizeof (*hdr) + hdr->hlength;

  /* send all the data and any padding */
  if (pdu_length % PAD_WORD_LEN)
          pad_bytes = PAD_WORD_LEN - (pdu_length % PAD_WORD_LEN);
  else
          pad_bytes = 0;

  if (conn->kernel_io) 
  {
          //if (conn->send_pdu_begin(session->ctrl_fd, session, conn, end - header, ntoh24(hdr->dlength) + pad_bytes)) 
          if(ksession_send_pdu_begin(session->ctrl_fd, session, conn, end - header, ntoh24(hdr->dlength) + pad_bytes))
          {
                  ret = 0;
                  goto done;
          }
          //conn->send_pdu_timer_add(conn, timeout);
  }
  //Renjs
  printf("afer if (conn->kernel_io)   \n");
  while (header < end) 
  {
          vec[0].iov_base = header;
          vec[0].iov_len = end - header;
          printf("before rc = ctldev_writev(session->ctrl_fd, 0, vec, 1);\n");
          if(session == NULL)
            printf("session == NULL!   \n");
          rc = ctldev_writev(session->ctrl_fd, 0, vec, 1);
          printf("after rc = ctldev_writev(session->ctrl_fd, 0, vec, 1);\n");
          //rc = iscsi_writev(session->ctrl_fd, 0, vec, 1);
          printf("send_pdu ctrl_fd =%d\n", session->ctrl_fd);
          //printf("header pdu sent = %s\n", header);


          /*
             if (timedout) {
             log_error("socket %d write timed out",
             conn->socket_fd);
             ret = 0;
             goto done;
             } else */

          if ((rc <= 0)) 
          {
                  printf("send header error!\n");
                  //LOG_CONN_FAIL(conn);
                  ret = 0;
                  goto done;
          } 
          else 
                  if (rc > 0) 
                  {
                          printf("wrote %d bytes of PDU header\n", rc);
                          header += rc;
                  }

  }

  end = data + ntoh24(hdr->dlength);
  remaining = ntoh24(hdr->dlength) + pad_bytes;

  printf("before   while (remaining > 0) \n");
  while (remaining > 0) 
  {
          printf("remaining = %d\n", remaining);

          vec[0].iov_base = data;
          vec[0].iov_len = end - data;
          vec[1].iov_base = (void *) &pad;
          vec[1].iov_len = pad_bytes;

          rc = ctldev_writev(session->ctrl_fd, 0, vec, 2);

		//rc = iscsi_writev(session->ctrl_fd, 0, vec, 2);
		printf("send_pdu ctrl_fd =%d\n", session->ctrl_fd);
		printf("data pdu sent = %s\n", data);
		printf("pad pdu sent = %c%c%c%c\n", pad[0],pad[1],pad[2],pad[3]);
	
		/*
		if (timedout) {
			log_error("socket %d write timed out",
			       conn->socket_fd);
			ret = 0;
			goto done;
		} else */

		if ((rc <= 0)) 
		{
			//LOG_CONN_FAIL(conn);
			printf("send data error!\n");
			ret = 0;
			goto done;
		} else 

		if (rc > 0) 
		{
			printf("wrote %d bytes of PDU data\n", rc);
			remaining -= rc;

			if (data < end) 
			{
				data += rc;
				if (data > end)
					data = end;
			}
		}
		
	}
printf("before if (conn->kernel_io)   !!!!!!!\n");
	if (conn->kernel_io) 
	{
		//if (conn->send_pdu_end(session->ctrl_fd, session, conn)) 
		if (ksession_send_pdu_end(session->ctrl_fd, session, conn)) 
		{
			ret = 0;
			goto done;
		}
	}

	ret = 1;

      done:
	//if (!conn->kernel_io) {
	//	alarm(0);
	//	sigaction(SIGALRM, &old, NULL);
	//	timedout = 0;
	//}
	return ret;
}

//int iscsi_recv_pdu(uiscsi_conn_t *conn, struct iscsi_hdr *hdr, int hdr_digest, char *data, int max_data_length, int data_digest, int timeout)
int iscsi_recv_pdu(uiscsi_conn_t *conn, struct iscsi_hdr *hdr, int hdr_digest, char *data, uint32_t data_size, int max_data_length, int data_digest, int timeout)
{
	uint32_t h_bytes = 0;
	uint32_t ahs_bytes = 0;
	uint32_t d_bytes = 0;
	uint32_t ahslength = 0;
	uint32_t dlength = 0;
	uint32_t pad = 0;
	int rlen = 0;
	int failed = 0;
	
	//char *header = (char *) hdr;
	char *end = data + max_data_length;
	
	//struct sigaction action;
	//struct sigaction old;
	unsigned long pdu_handle;
	int pdu_size;
	uiscsi_session_t *session = conn->session;

	// memset(data, 0, max_data_length);

	/* set a timeout, since the socket calls may take a long
	 * time to timeout on their own
	 */
	//if (!conn->kernel_io) {
	//	memset(&action, 0, sizeof (struct sigaction));
	//	memset(&old, 0, sizeof (struct sigaction));
	//	action.sa_sigaction = NULL;
	//	action.sa_flags = 0;
	//	action.sa_handler = sigalarm_handler;
	//	sigaction(SIGALRM, &action, &old);
	//	timedout = 0;
	//	alarm(timeout);
	//} 
	//else 
	//{
		//if (conn->recv_pdu_begin(session->ctrl_fd, conn,
		//		conn->recv_handle, &pdu_handle, &pdu_size)) {
		//	failed = 1;
		//	goto done;
		//}
	//}

	/* read a response header */
	/*do {
		rlen = ctldev_read(session->ctrl_fd, header,
				sizeof (*hdr) - h_bytes);
		if (timedout) {
			log_error("socket %d header read timed out",
			       conn->socket_fd);
			failed = 1;
			goto done;
		} 
		else if (rlen == 0) {
			LOG_CONN_CLOSED(conn);
			failed = 1;
			goto done;
		} 
		else if ((rlen < 0) && (errno != EAGAIN)) {
			LOG_CONN_FAIL(conn);
			failed = 1;
			goto done;
		} else if (rlen > 0) {
			log_debug(4, "read %d bytes of PDU header", rlen);
			header += rlen;
			h_bytes += rlen;
		}
	} while (h_bytes < sizeof (*hdr));*/


	printf ("read PDU header, opcode 0x%x, dlength %u, data %p, max %u\n", hdr->opcode, ntoh24(hdr->dlength), data, max_data_length);

	/* check for additional headers */
	ahslength = hdr->hlength;	/* already includes padding */
	
	if (ahslength) {
		//log_warning("additional header segment length %u not supported", ahslength);
		printf("additional header segment length %u not supported\n", ahslength);
		failed = 1;
		goto done;
	}

	/* read exactly what we expect, plus padding */
	dlength = hdr->dlength[0] << 16;
	dlength |= hdr->dlength[1] << 8;
	dlength |= hdr->dlength[2];

	/* if we only expected to receive a header, exit */
	if (dlength == 0)
		goto done;

	if (data + dlength >= end) {
		//log_warning("buffer size %u too small for data length %u", max_data_length, dlength);
		printf("buffer size %u too small for data length %u\n", max_data_length, dlength);
		failed = 1;
		goto done;
	}

	printf("hlength in hdr = %u, dlength in hdr = %u, data_size = %u \n", ahslength, dlength, data_size);
	
	/* read the rest into our buffer */
	d_bytes = 0;
	/*while (d_bytes < dlength) {
		rlen = ctldev_read(session->ctrl_fd, data + d_bytes,
				dlength - d_bytes);
		if (timedout) {
			log_error("socket %d data read timed out",
			       conn->socket_fd);
			failed = 1;
			goto done;
		} else if (rlen == 0) {
			LOG_CONN_CLOSED(conn);
			failed = 1;
			goto done;
		} else if ((rlen < 0 && errno != EAGAIN)) {
			LOG_CONN_FAIL(conn);
			failed = 1;
			goto done;
		} else if (rlen > 0) {
			log_debug(4, "read %d bytes of PDU data", rlen);
			d_bytes += rlen;
		}
	}*/

	/* handle PDU data padding.
	 * data is padded in case of kernel_io */
	pad = dlength % PAD_WORD_LEN;
	/*if (pad && !conn->kernel_io) {
		int pad_bytes = pad = PAD_WORD_LEN - pad;
		char bytes[PAD_WORD_LEN];

		while (pad_bytes > 0) {
			rlen = read(conn->socket_fd, &bytes, pad_bytes);
			if (timedout) {
				log_error("socket %d pad read timed out",
				       conn->socket_fd);
				failed = 1;
				goto done;
			} else if (rlen == 0) {
				LOG_CONN_CLOSED(conn);
				failed = 1;
				goto done;
			} else if ((rlen < 0 && errno != EAGAIN)) {
				LOG_CONN_FAIL(conn);
				failed = 1;
				goto done;
			} else if (rlen > 0) {
				log_debug(4, "read %d pad bytes", rlen);
				pad_bytes -= rlen;
			}
		}
	}*/

	//if (log_level > 0) {
		switch (hdr->opcode) {
		case ISCSI_OP_TEXT_RSP:
			//log_debug(4,
			//	 "finished reading text PDU, %u hdr, %u "
			//	 "ah, %u data, %u pad",
			//	 h_bytes, ahs_bytes, d_bytes, pad);
			printf("iscsi_recv_pdu: finished reading text PDU \n");
			iscsi_log_text(hdr, data);
			break;
		case ISCSI_OP_LOGIN_RSP:{
				struct iscsi_login_rsp *login_rsp =  (struct iscsi_login_rsp *) hdr;

				//log_debug(4,
				//	 "finished reading login PDU, %u hdr, "
				//	 "%u ah, %u data, %u pad",
				//	 h_bytes, ahs_bytes, d_bytes, pad);
				printf( "iscsi_recv_pdu: login current stage %d, next stage %d, transit 0x%x\n",
					 ISCSI_LOGIN_CURRENT_STAGE(login_rsp->flags),
					 ISCSI_LOGIN_NEXT_STAGE(login_rsp->flags),
					 login_rsp->flags & ISCSI_FLAG_LOGIN_TRANSIT);
				printf("iscsi_recv_pdu: finished reading loginrsp PDU \n");
				iscsi_log_text(hdr, data);
				break;
			}
		case ISCSI_OP_ASYNC_EVENT:
			/* FIXME: log the event info */
			break;
		default:
			break;
		}
	//}

done:
	//if (!conn->kernel_io) {
	//	alarm(0);
	//	sigaction(SIGALRM, &old, NULL);
	//} else {
		/* finalyze receive transaction */
		//if (conn->recv_pdu_end(session->ctrl_fd, conn, pdu_handle)) {
		//	failed = 1;
		//}
		//conn->send_pdu_timer_remove(conn);
	//}

	//if (timedout || failed) {
	//	timedout = 0;
	//	return 0;
	//}

	//return h_bytes + ahs_bytes + d_bytes;
	return ahslength + dlength;
}
