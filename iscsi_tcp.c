/*
 * iSCSI Initiator over TCP/IP Data-Path
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
 *
 * Credits:
 * Christoph Hellwig	: For reviewing the code, for comments and suggestions.
 * Mike Christie	: For reviewing the code, for comments and suggestions.
 */


/*
#include <linux/types.h>
#include <linux/list.h>
#include <linux/inet.h>
#include <linux/blkdev.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/scatterlist.h>
#include <net/tcp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_request.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>
*/
#include "iSCSI-typedefs.h"
#include <stdio.h>
#include <stdint.h>
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

#include "initiator.h"
#include "iscsi_tcp.h"
//#include "app-iscsi-cb.h"
//#include "SCSI/device.h"
#define min(x,y) ((x)<(y)?(x):(y))









//MODULE_AUTHOR("Dmitry Yusupov <dmitry_yus@yahoo.com>, "
//	      "Alex Aizman <itn780@yahoo.com>");
//MODULE_DESCRIPTION("iSCSI/TCP data-path");
//MODULE_LICENSE("GPL");

/* #define DEBUG_TCP */
/* #define DEBUG_SCSI */
/* #define DEBUG_ASSERT */

/*
#ifdef DEBUG_TCP
#define debug_tcp(fmt...) printk("tcp: " fmt)
#else
#define debug_tcp(fmt...)
#endif

#ifdef DEBUG_SCSI
#define debug_scsi(fmt...) printk("scsi: " fmt)
#else
#define debug_scsi(fmt...)
#endif

#ifndef DEBUG_ASSERT
#ifdef BUG_ON
#undef BUG_ON
#endif
#define BUG_ON(expr)
#endif
*/
/* global data */
/*static kmem_cache_t *taskcache;
*/

//Renjs
extern int numwin ;
extern int ittdec;
extern uint64_t run;
extern CVMX_SHARED int ctw;
int iscsi_queuecommand(struct scsi_cmnd *sc, void (*done)(struct scsi_cmnd *));


#ifdef SG
static inline void
iscsi_buf_init_virt(struct iscsi_buf *ibuf, char *vbuf, int size)
{
	sg_init_one(&ibuf->sg, (u8 *)vbuf, size);
	ibuf->sent = 0;
}

static inline void
iscsi_buf_init_sg(struct iscsi_buf *ibuf, struct scatterlist *sg)
{
	ibuf->sg.page = sg->page;
	ibuf->sg.offset = sg->offset;
	ibuf->sg.length = sg->length;
	ibuf->sent = 0;
}



static inline void
iscsi_buf_init_hdr(struct iscsi_conn *conn, struct iscsi_buf *ibuf,  char *vbuf, u8 *crc)
{
	iscsi_buf_init_virt(ibuf, vbuf, sizeof(struct iscsi_hdr));
	if (conn->hdrdgst_en) {
		crypto_digest_init(conn->tx_tfm);
		crypto_digest_update(conn->tx_tfm, &ibuf->sg, 1);
		crypto_digest_final(conn->tx_tfm, crc);
		ibuf->sg.length += sizeof(uint32_t);
	}
}
#endif





static inline int
iscsi_buf_left(struct iscsi_buf *ibuf)
{
	int rc;
	//rc = ibuf->sg.length - ibuf->sent;
	rc = ibuf->length - ibuf->sent;
	//BUG_ON(rc < 0);
	return rc;
}

#define iscsi_conn_get(rdd) (struct iscsi_conn*)(rdd)->arg.data
#define iscsi_conn_set(rdd, conn) (rdd)->arg.data = conn



static struct scsi_host_template iscsi_sht = 
{
	.name			= "iSCSI Initiator over TCP/IP, v."ISCSI_DRV_VERSION,
        .queuecommand           = iscsi_queuecommand,
	.can_queue		= ISCSI_XMIT_CMDS_MAX - 1,
	.sg_tablesize		= ISCSI_SG_TABLESIZE,
	.cmd_per_lun		= ISCSI_CMD_PER_LUN,
       // .eh_abort_handler       = iscsi_eh_abort,
        .use_clustering         = 0,  //DISABLE_CLUSTERING
	.proc_name		= "iscsi_tcp",
	.this_id		= -1,
};




 int
kiscsi_mhdr_extract(struct iscsi_conn *conn)
{
	//struct sk_buff *skb = conn->in.skb;
	char *iscsi_skb = conn->in.iscsi_skb;

	if (conn->in.copy >= conn->hdr_size && conn->in_progress != IN_PROGRESS_HEADER_GATHER) 
	{	
		/*
		 * Zero-copy PDU Header: using connection context
		 * to store header pointer.
		 */
		//if (skb_shinfo(skb)->frag_list == NULL && !skb_shinfo(skb)->nr_frags) 
		//{
			//conn->in.hdr = (struct iscsi_hdr *) ((char*)skb->data + conn->in.offset);
			conn->in.hdr = (struct iscsi_hdr *) (iscsi_skb + conn->in.offset);
		//} 
		//else {
			/* ignoring return code since we checked
			 * in.copy before */
			//skb_copy_bits(skb, conn->in.offset, &conn->hdr, conn->hdr_size);
			//conn->in.hdr = &conn->hdr;
			memcpy(&conn->hdr, iscsi_skb + conn->in.offset, conn->hdr_size);
			conn->in.hdr = &conn->hdr;
		//}
		
		//printf("kiscsi_hdr_extract: conn->in.offset = %d, conn->hdr_size = %d\n", conn->in.offset , conn->hdr_size);
		//printf("kiscsi_hdr_extract: conn->in.hdr = ");
		//int i=0;
		//for(i=0;i<conn->hdr_size;i++)
		//{
		//	printf("%x ", ((unsigned char *)conn->in.hdr)[i]);
		//}
		//printf("\n");
		
		conn->in.offset += conn->hdr_size;
		conn->in.copy -= conn->hdr_size;
		conn->in.hdr_offset = 0;
	} 

	else 
	{
		int copylen;

		/*
		 * PDU header scattered accross SKB's,
		 * copying it... This'll happen quite rarely.
		 */
		if (conn->in_progress == IN_PROGRESS_WAIT_HEADER) 
		{
			//skb_copy_bits(skb, conn->in.offset, &conn->hdr, conn->in.copy);
			memcpy(&conn->hdr, iscsi_skb + conn->in.offset, conn->in.copy);
			
			conn->in_progress = IN_PROGRESS_HEADER_GATHER;
			conn->in.hdr_offset = conn->in.copy;
			conn->in.offset += conn->in.copy;
			conn->in.copy = 0;

			//debug_tcp("PDU gather #1 %d bytes!\n", conn->in.hdr_offset);
			printf("PDU gather #1 %d bytes!\n", conn->in.hdr_offset);
			return -EAGAIN;
		}

		copylen = conn->hdr_size - conn->in.hdr_offset;
		if (copylen > conn->in.copy) 
		{
			printf("iSCSI: PDU gather failed! copylen %d conn->in.copy %d\n", copylen, conn->in.copy);
			//iscsi_control_cnx_error(conn->handle, ISCSI_ERR_PDU_GATHER_FAILED);
			return 0;
		}
		//debug_tcp("PDU gather #2 %d bytes!\n", copylen);
		printf ("PDU gather #2 %d bytes!\n", copylen);

		//skb_copy_bits(skb, conn->in.offset, (char*)&conn->hdr + conn->in.hdr_offset, copylen);
		memcpy((char*)&conn->hdr + conn->in.hdr_offset, iscsi_skb + conn->in.offset, copylen);

		conn->in.offset += copylen;
		conn->in.copy -= copylen;
		conn->in.hdr_offset = 0;
		conn->in.hdr = &conn->hdr;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

	return 0;
}

int kiscsi_tcp_data_recv1(struct iscsi_conn *conn, struct scsi_cmnd *sc )
{ 
	int socket = conn->socket;
	int res = 0;
	int rc = 0;
	conn->data_copied = 0;
        
        if(conn->in_progress == IN_PROGRESS_WAIT_HEADER)
        {
                 conn->head_recv %= 48;
                res = cvm_so_recv(socket, (char *)conn->in.iscsi_skb + conn->head_recv, 48 - conn->head_recv, 0);
                 if(res != 48)
                 {
                 }
                 if(res < 0)
                 {
                 return res;
                 }

                if(res >= 0 && res <(48 - conn->head_recv))
                {
                  conn->in.total_len += res;
                  conn->head_recv += res;
                  return 0;
                }
                if(res == (48 - conn->head_recv))
                {
                  conn->head_recv = 0;
                  conn->in.total_len = 48;
                 }
                if(res <= 0)
                  return res;                 
        }
        conn->in.copy = 48;
        conn->in.offset = 0;
        conn->in.len = 48;
more:
        conn->in.copied = 0;
        if (conn->in_progress == IN_PROGRESS_WAIT_HEADER || conn->in_progress == IN_PROGRESS_HEADER_GATHER)
        {
                // ≥Èø≤ø–ø
                rc = kiscsi_hdr_extract(conn);
                if (rc == -EAGAIN)
                {
                        printf("rc == -EAGAIN\n");
                        goto nomore;
                }

                if(sc == NULL)
                {
                        //Renjs –º”Îror¥¶¿∑Ωø
                        struct iscsi_hdr * hdr;
                        struct itt_work * work;
                        hdr = conn->in.hdr;
                        if(hdr->itt == 0xffffffff) //NOOP_IN
                        {
                                printf("NOOPIN 2\n");
                                conn->in.total_len = 0;
                                return 0;
                                sc = NULL;
                                work = NULL;
                        }
                        else if(hdr->itt > ITTLENGTH)
                        {
                                printf("hdr->itt > ITTLENGTH, %d\n", hdr->itt);
                                return 0;
                        }
                        else
                        {
                                if(conn->itt_queue[hdr->itt] == NULL){
                                     

                                        return 0;
                                }
                                if(conn->itt_queue[hdr->itt] != NULL)
                                {
                                        work = conn->itt_queue[hdr->itt];
                                        sc = work->sc;
                                }
                        }
                }

                rc = kiscsi_hdr_recv(conn, sc);  // ≥ø¶∑µªÿ
                if (!rc && conn->in.datalen)
                {
                        conn->in_progress = IN_PROGRESS_DATA_RECV;
                } 
                else if (rc) 
                {
                        printf("kiscsi_tcp_data_recv: [1]iSCSI: bad hdr rc (%d) \n", rc);
                        return 0;
                }

        }

 
        if (conn->in_progress == IN_PROGRESS_DATA_RECV && conn->in.total_len - 48 < conn->in.datalen) 
        {
                if(sc == NULL)
                {
                        //Renjs –º”Îror¥¶¿∑Ωø
                        struct iscsi_hdr * hdr;
                        struct itt_work * work;
                        hdr = conn->in.hdr;
                        if(hdr->itt == 0xffffffff) //NOOP_IN
                        {
                                printf("NOOPIN 2\n");
                                return 0;
                                sc = NULL;
                                work = NULL;
                        }
                        else if(hdr->itt > ITTLENGTH)
                        {
                                printf("hdr->itt > ITTLENGTH, %d\n", hdr->itt);
                                return 0;
                        }
                        else
                        {
                                if(conn->itt_queue[hdr->itt] == NULL){
                                        printf("IN_PROGRESS_DATA_RECV  %d is NULL\n", hdr->itt);

                                        return 0;
                                }
                                if(conn->itt_queue[hdr->itt] != NULL)
                                {
                                        work = conn->itt_queue[hdr->itt];
                                        sc = work->sc;
                                }
                        }
                }
                if(conn->in.hdr->opcode == ISCSI_OP_SCSI_DATA_IN)
                {
                        if(conn->in.hdr->flags == 0x81 || conn->in.hdr->flags == 0x80 || conn->in.hdr->flags == 0x00 || conn->in.hdr->flags == 0x83)
                        {
                                {
                                        {
                                                int buffer_len = 0;
                                                if(sc == NULL)
                                                  printf("sc == NULL  \n");
                                                data_list_t * data_head = (data_list_t *) sc->request_buffer_ptr;
                                                
                                                do
                                                {
                                                        buffer_len = data_head->data_len - data_head->copied;
                                                        if(buffer_len > conn->in.datalen - (conn->in.total_len - 48))
                                                                buffer_len = conn->in.datalen - (conn->in.total_len - 48);
                                                        char * buf_ptr = ((char*)cvmx_phys_to_ptr(data_head->data_ptr)) + data_head->offset + data_head->copied;
                              
                                                        res = cvm_so_recv(socket, buf_ptr, buffer_len, 0);
                                    
                                                        if(res >= 0)
                                                        {
                                                                conn->data_copied += res;
                                                                conn->in.total_len += res;
                                                                data_head->copied += res;
                                                                if(data_head->copied == data_head->data_len)
                                                                {
                                                                        data_head = data_head->next;
                                                                        sc->request_buffer_ptr = data_head;
                                                                }
                                                                if(conn->in.total_len - 48 == conn->in.datalen)
                                                                {
                                    
                                                                  conn->in_progress = IN_PROGRESS_WAIT_HEADER;
                                                                  conn->in.total_len = 0;
                                                                  break;
                                                                }
                                                        }
                                                        if(res <= 0)
                                                           return res;
                                                }while(res > 0);
                                        } 
                                }

                        }
                }
        }

nomore:
        if(sc->app_work != NULL)
        {
                if(conn->in.hdr->flags == 0x81 && conn->in.total_len == 0 )
                {
                        if(conn->itt_queue[conn->in.hdr->itt] != NULL)
                        {

                                cvm_common_free_fpa_buffer((void *)conn->itt_queue[conn->in.hdr->itt], CVMX_FPA_WQE_POOL, 0);
                                conn->itt_queue[conn->in.hdr->itt] = NULL;
                        }

                        iSCSI_context * current_context = (iSCSI_context *) sc->context;
                        if(current_context->itt_used == 0)
                                printf("current_context itt_used is 0\n");
                        current_context->itt_used--;
                        ittdec++;

                        cvmx_wqe_t * work = (cvmx_wqe_t *)sc->app_work;
                        iSCSI_Params * params_ptr = (iSCSI_Params *) work->packet_data;
                        data_list_t * data_head = (data_list_t *)params_ptr->data_head;
                        while(data_head != NULL)
                        {
                                data_list_t * temp_data_head = data_head;
                                data_head = data_head->next; 
                                cvm_common_free_fpa_buffer((void*)cvmx_phys_to_ptr(temp_data_head->data_ptr), CVMX_FPA_PACKET_POOL, 0);
                                cvm_common_free_fpa_buffer((void*)temp_data_head, CVMX_FPA_WQE_POOL, 0);
                        }
                        cvm_common_free_fpa_buffer((void*)work, CVMX_FPA_WQE_POOL, 0);

                        cvm_common_free_fpa_buffer((void*)sc, CVMX_FPA_PACKET_POOL, 0);
                }
        }
        return conn->data_copied;

again:
        printf("return again, %d\n", conn->in.offset);
        return conn->in.offset;
}

 int
kiscsi_hdr_extract(struct iscsi_conn *conn)
{
	//struct sk_buff *skb = conn->in.skb;
	char *iscsi_skb = conn->in.iscsi_skb;

	if (conn->in.copy >= conn->hdr_size && conn->in_progress != IN_PROGRESS_HEADER_GATHER) 
	{	
		/*
		 * Zero-copy PDU Header: using connection context
		 * to store header pointer.
		 */
		//if (skb_shinfo(skb)->frag_list == NULL && !skb_shinfo(skb)->nr_frags) 
		//{
			//conn->in.hdr = (struct iscsi_hdr *) ((char*)skb->data + conn->in.offset);
			conn->in.hdr = (struct iscsi_hdr *) (iscsi_skb + conn->in.offset);
		//} 
		//else {
			/* ignoring return code since we checked
			 * in.copy before */
			//skb_copy_bits(skb, conn->in.offset, &conn->hdr, conn->hdr_size);
			//conn->in.hdr = &conn->hdr;
			memcpy(&conn->hdr, iscsi_skb + conn->in.offset, conn->hdr_size);
			conn->in.hdr = &conn->hdr;
		//}
		
		//printf("kiscsi_hdr_extract: conn->in.offset = %d, conn->hdr_size = %d\n", conn->in.offset , conn->hdr_size);
		//printf("kiscsi_hdr_extract: conn->in.hdr = ");
		//int i=0;
		//for(i=0;i<conn->hdr_size;i++)
		//{
		//	printf("%x ", ((unsigned char *)conn->in.hdr)[i]);
		//}
		//printf("\n");
		
		conn->in.offset += conn->hdr_size;
		conn->in.copy -= conn->hdr_size;
		conn->in.hdr_offset = 0;
	} 

	else 
	{
    printf("kiscsi_hdr_extract in else\n");
		int copylen;

		/*
		 * PDU header scattered accross SKB's,
		 * copying it... This'll happen quite rarely.
		 */
		if (conn->in_progress == IN_PROGRESS_WAIT_HEADER) 
		{
			//skb_copy_bits(skb, conn->in.offset, &conn->hdr, conn->in.copy);
			memcpy(&conn->hdr, iscsi_skb + conn->in.offset, conn->in.copy);
			
			conn->in_progress = IN_PROGRESS_HEADER_GATHER;
			conn->in.hdr_offset = conn->in.copy;
			conn->in.offset += conn->in.copy;
			conn->in.copy = 0;

			//debug_tcp("PDU gather #1 %d bytes!\n", conn->in.hdr_offset);
			printf("PDU gather #1 %d bytes!\n", conn->in.hdr_offset);
			return -EAGAIN;
		}

		copylen = conn->hdr_size - conn->in.hdr_offset;
		if (copylen > conn->in.copy) 
		{
			printf("iSCSI: PDU gather failed! copylen %d conn->in.copy %d\n", copylen, conn->in.copy);
			//iscsi_control_cnx_error(conn->handle, ISCSI_ERR_PDU_GATHER_FAILED);
			return 0;
		}
		//debug_tcp("PDU gather #2 %d bytes!\n", copylen);
		printf ("PDU gather #2 %d bytes!\n", copylen);

		//skb_copy_bits(skb, conn->in.offset, (char*)&conn->hdr + conn->in.hdr_offset, copylen);
		memcpy((char*)&conn->hdr + conn->in.hdr_offset, iscsi_skb + conn->in.offset, copylen);

		conn->in.offset += copylen;
		conn->in.copy -= copylen;
		conn->in.hdr_offset = 0;
		conn->in.hdr = &conn->hdr;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

	return 0;
}













static void
iscsi_ctask_cleanup(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	//printf("iscsi_ctask_cleanup: entering!!!!!!!!!!\n ");
	struct scsi_cmnd *sc = ctask->sc;
	struct iscsi_session *session = conn->session;

	//spin_lock(&session->lock);
	if (ctask->in_progress == IN_PROGRESS_IDLE) {
		//spin_unlock(&session->lock);
		return;
	}
	if (sc->sc_data_direction == DMA_TO_DEVICE) {
		//printf("iscsi_ctask_cleanup: DMA to DEVICE !!!!!   \n");
		//struct iscsi_data_task *dtask, *n;
		// WRITE: cleanup Data-Out's if any 
		//spin_lock(&conn->lock);
		//list_for_each_entry_safe(dtask, n, &ctask->dataqueue, item) {
		//	list_del(&dtask->item);
		//	mempool_free(dtask, ctask->datapool);
		//}
		//spin_unlock(&conn->lock);
	}
	ctask->in_progress = IN_PROGRESS_IDLE;
	//__kfifo_put(session->cmdpool.queue, (void*)&ctask, sizeof(void*));
	//spin_unlock(&session->lock);
}




/*
 * SCSI Command Response processing
 */
static int
iscsi_cmd_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	//printf("iscsi_cmd_rsp: entering!!!!!!!!!!\n ");
	int rc = 0;
	struct iscsi_cmd_rsp *rhdr = (struct iscsi_cmd_rsp *)conn->in.hdr;
	struct iscsi_session *session = conn->session;
	struct scsi_cmnd *sc = ctask->sc;
	//int max_cmdsn = ntohl(rhdr->max_cmdsn);
	//int exp_cmdsn = ntohl(rhdr->exp_cmdsn);
	int max_cmdsn = (rhdr->max_cmdsn);
	int exp_cmdsn = (rhdr->exp_cmdsn);

	   //printf("iscsi_cmd_rsp: max_cmdsn=rhdr->max_cmdsn=%d, exp_cmdsn=rhdr->exp_cmdsn=%d \n", rhdr->max_cmdsn, rhdr->exp_cmdsn);

	if (max_cmdsn < exp_cmdsn - 1) {
		rc = ISCSI_ERR_MAX_CMDSN;
		sc->result = (DID_ERROR << 16);
		goto fault;
	}
	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;
	//conn->exp_statsn = ntohl(rhdr->statsn) + 1;

	conn->exp_statsn = (rhdr->statsn) + 1;
	sc->result = (DID_OK << 16) | rhdr->cmd_status;

	if (rhdr->response == ISCSI_STATUS_CMD_COMPLETED) 
	{
		if (rhdr->cmd_status == SAM_STAT_CHECK_CONDITION &&  conn->senselen) 
		{
			int sensecopy = min(conn->senselen, SCSI_SENSE_BUFFERSIZE);
			memcpy(sc->sense_buffer, conn->data + 2, sensecopy);
			printf("iscsi_cmd_rsp: copied %d bytes of sense\n", sensecopy);
		}

		if (sc->sc_data_direction != DMA_TO_DEVICE ) 
		{
			if (rhdr->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
				//int res_count = ntohl(rhdr->residual_count);
				int res_count = (rhdr->residual_count);
				
				if (res_count > 0 &&  res_count <= sc->request_bufflen) 
				{
					sc->resid = res_count;
					//printf("iscsi_cmd_rsp: sc->resid = res_count = %d\n", res_count);
				} 
				else 
				{
					sc->result = (DID_BAD_TARGET << 16) |  rhdr->cmd_status;
					rc = ISCSI_ERR_BAD_TARGET;
					//printf("iscsi_cmd_rsp: rc = ISCSI_ERR_BAD_TARGET \n");
					goto fault;
				}
			} 
			else if (rhdr->flags& ISCSI_FLAG_CMD_BIDI_UNDERFLOW) {
				sc->result = (DID_BAD_TARGET << 16) | rhdr->cmd_status;
				rc = ISCSI_ERR_BAD_TARGET;
				goto fault;
			} 
			else if (rhdr->flags & ISCSI_FLAG_CMD_OVERFLOW) {
				//sc->resid = ntohl(rhdr->residual_count);
				sc->resid = (rhdr->residual_count);
			}
		}
	} 
	else {
		sc->result = (DID_ERROR << 16);
		rc = ISCSI_ERR_BAD_TARGET;
		goto fault;
	}

fault:
	//debug_scsi("done [sc %lx res %d itt 0x%x]\n", (long)sc, sc->result, ctask->itt);
	//printf ("iscsi_cmd_rsp: done [(long)sc = %lx, sc->result = %d, sc->result = 0x%x]\n", (long)sc, sc->result, sc->result);
	iscsi_ctask_cleanup(conn, ctask);
	sc->scsi_done(sc);
	return rc;
}





/*
 * SCSI Data-In Response processing
 */
static int
iscsi_data_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	//printf("iscsi_data_rsp: entering !!!!!!!!!!!!\n");
	struct iscsi_data_rsp *rhdr = (struct iscsi_data_rsp *)conn->in.hdr;
	struct iscsi_session *session = conn->session;
	//int datasn = ntohl(rhdr->datasn);
	//int max_cmdsn = ntohl(rhdr->max_cmdsn);
	//int exp_cmdsn = ntohl(rhdr->exp_cmdsn);

	int datasn = (rhdr->datasn);
	int max_cmdsn = (rhdr->max_cmdsn);
	int exp_cmdsn = (rhdr->exp_cmdsn);

	//printf("iscsi_data_rsp: datasn=rhdr->datasn=%d, max_cmdsn=rhdr->max_cmdsn=%d, exp_cmdsn=rhdr->exp_cmdsn=%d \n", rhdr->datasn, rhdr->max_cmdsn, rhdr->exp_cmdsn);

	 // setup Data-In byte counter (gets decremented..)
	ctask->data_count = conn->in.datalen;

	if (conn->in.datalen == 0)
		return 0;

	if (max_cmdsn < exp_cmdsn -1)
		return ISCSI_ERR_MAX_CMDSN;

	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;

	//printf("iscsi_data_rsp: ctask->datasn = %d, rhdr->datasn = %d \n");
	//if (ctask->datasn != datasn)
	//	return ISCSI_ERR_DATASN;

	ctask->datasn++;
	//ctask->data_offset = ntohl(rhdr->offset);
	ctask->data_offset = (rhdr->offset);

	//printf("iscsi_data_rsp: ctask->data_offset = (rhdr->offset) = %d\n", rhdr->offset);
	//printf("iscsi_data_rsp: conn->in.datalen = ntoh24(hdr->dlength) = %d\n", conn->in.datalen);
	//printf("iscsi_data_rsp: ctask->total_length =   = %d\n", ctask->total_length);
	
	//if (ctask->data_offset + conn->in.datalen > ctask->total_length) {
	//	return ISCSI_ERR_DATA_OFFSET;
	//}

	if (rhdr->flags & ISCSI_FLAG_DATA_STATUS) 
	{
		struct scsi_cmnd *sc = ctask->sc;
		//conn->exp_statsn = ntohl(rhdr->statsn) + 1;
		conn->exp_statsn = (rhdr->statsn) + 1;

		if (rhdr->flags & ISCSI_FLAG_CMD_UNDERFLOW) 
		{
			//int res_count = ntohl(rhdr->residual_count);
			int res_count = (rhdr->residual_count);
			if (res_count > 0 &&
			    res_count <= sc->request_bufflen) {
				sc->resid = res_count;
			} else {
				sc->result = (DID_BAD_TARGET << 16) |
					rhdr->cmd_status;
				return ISCSI_ERR_BAD_TARGET;
			}
		} 
		else if (rhdr->flags& ISCSI_FLAG_CMD_BIDI_UNDERFLOW) {
			sc->result = (DID_BAD_TARGET << 16) |
				rhdr->cmd_status;
			return ISCSI_ERR_BAD_TARGET;
		} 
		else if (rhdr->flags & ISCSI_FLAG_CMD_OVERFLOW) {
			//sc->resid = ntohl(rhdr->residual_count);
			sc->resid = (rhdr->residual_count);
		}
	}
	return 0;
}




/*
 * iscsi_solicit_data_init - initialize first Data-Out
 *
 * Initialize first Data-Out within this R2T sequence and finds
 * proper data_offset within this SCSI command.
 *
 * This function is called with connection lock taken.
 */
static void
iscsi_solicit_data_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask, struct iscsi_r2t_info *r2t)
{
	struct iscsi_data *hdr;
	struct iscsi_data_task *dtask;
	struct scsi_cmnd *sc = ctask->sc;

	//dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	dtask = malloc(sizeof(struct iscsi_data_task));
	hdr = &dtask->hdr;
	hdr->rsvd2[0] = hdr->rsvd2[1] = hdr->rsvd3 =
		hdr->rsvd4 = hdr->rsvd5 = hdr->rsvd6 = 0;
	hdr->ttt = r2t->ttt;
	//hdr->datasn = htonl(r2t->solicit_datasn);
	hdr->datasn = (r2t->solicit_datasn);
	r2t->solicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	memset(hdr->lun, 0, 8);
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = r2t->exp_statsn;
	//hdr->offset = htonl(r2t->data_offset);
	hdr->offset = r2t->data_offset;
	if (r2t->data_length > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		r2t->data_count = conn->max_xmit_dlength;
		hdr->flags = 0;
	} 
	else {
		hton24(hdr->dlength, r2t->data_length);
		r2t->data_count = r2t->data_length;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}

	r2t->sent = 0;

	//iscsi_buf_init_hdr(conn, &r2t->headbuf, (char*)hdr, (u8 *)dtask->hdrext);
	r2t->headbuf.buffer = (char *)hdr;
	r2t->headbuf.length = sizeof(struct iscsi_data);
	
	if (sc->use_sg) {
		printf("r2t SCSI using sg !!! \n");
		/*int i, sg_count = 0;
		struct scatterlist *sg = sc->request_buffer;

		r2t->sg = NULL;
		for (i = 0; i < sc->use_sg; i++, sg += 1) {
			// FIXME: prefetch ? 
			if (sg_count + sg->length > r2t->data_offset) {
				int page_offset;

				// sg page found! 

				// offset within this page 
				page_offset = r2t->data_offset - sg_count;

				//fill in this buffer 
				iscsi_buf_init_sg(&r2t->sendbuf, sg);
				r2t->sendbuf.sg.offset += page_offset;
				r2t->sendbuf.sg.length -= page_offset;

				//xmit logic will continue with next one 
				r2t->sg = sg + 1;
				break;
			}
			sg_count += sg->length;
		}
		//BUG_ON(r2t->sg == NULL);*/
	}
	else 
	{		
		//iscsi_buf_init_virt(&ctask->sendbuf, (char*)sc->request_buffer + r2t->data_offset, r2t->data_count);
		ctask->sendbuf.buffer = (char*)sc->request_buffer + r2t->data_offset;
		ctask->sendbuf.length =  r2t->data_count;
		ctask->sendbuf.offset = 0;
		ctask->sendbuf.sent = 0;	
	}
	//list_add(&dtask->item, &ctask->dataqueue);
}




/*
 * iSCSI R2T Response processing
 */
static int
iscsi_r2t_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	printf("in iscsi_r2t_rsp\n");
	struct iscsi_r2t_info *r2t;
	struct iscsi_session *session = conn->session;
	struct iscsi_r2t_rsp *rhdr = (struct iscsi_r2t_rsp *)conn->in.hdr;
	//uint32_t max_cmdsn = ntohl(rhdr->max_cmdsn);
	//uint32_t exp_cmdsn = ntohl(rhdr->exp_cmdsn);
	//int r2tsn = ntohl(rhdr->r2tsn);
	uint32_t max_cmdsn = (rhdr->max_cmdsn);
	uint32_t exp_cmdsn = (rhdr->exp_cmdsn);
	int r2tsn = (rhdr->r2tsn);
	
	if (conn->in.ahslen)
		return ISCSI_ERR_AHSLEN;

	if (conn->in.datalen)
		return ISCSI_ERR_DATALEN;

	if (ctask->exp_r2tsn && ctask->exp_r2tsn != r2tsn)
		return ISCSI_ERR_R2TSN;

	if (max_cmdsn < exp_cmdsn - 1)
		return ISCSI_ERR_MAX_CMDSN;

	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;

	// FIXME: use R2TSN to detect missing R2T 
	// fill-in new R2T associated with the task 
	//if (!__kfifo_get(ctask->r2tpool.queue, (void*)&r2t, sizeof(void*))) 
	//{
	//	return ISCSI_ERR_PROTO;
	//}
	r2t = malloc(sizeof(struct iscsi_r2t_info));
	
	r2t->exp_statsn = rhdr->statsn;
	//r2t->data_length = ntohl(rhdr->data_length);
	r2t->data_length = (rhdr->data_length);
	if (r2t->data_length == 0 ||
	    r2t->data_length > session->max_burst) {
		return ISCSI_ERR_DATALEN;
	}
	//r2t->data_offset = ntohl(rhdr->data_offset);
	r2t->data_offset = (rhdr->data_offset);
	if (r2t->data_offset + r2t->data_length > ctask->total_length) {
		return ISCSI_ERR_DATALEN;
	}
	r2t->ttt = rhdr->ttt; // no flip 
	r2t->solicit_datasn = 0;

	iscsi_solicit_data_init(conn, ctask, r2t);

	ctask->exp_r2tsn = r2tsn + 1;
	ctask->xmstate |= XMSTATE_SOL_HDR;
	
	//__kfifo_put(ctask->r2tqueue, (void*)&r2t, sizeof(void*));
	//__kfifo_put(conn->writequeue, (void*)&ctask, sizeof(void*));

	//schedule_work(&conn->xmitwork);
	kiscsi_xmitworker((void*)conn);
	kiscsi_tcp_data_recv(conn, NULL);
	return 0;
}





int
kiscsi_hdr_recv(struct iscsi_conn *conn, struct scsi_cmnd *sc )
{
	//printf("in kiscsi_hdr_recv, sc is %p\n", sc);
	int rc = 0;
	struct iscsi_hdr *hdr;
	struct iscsi_cmd_task *ctask;
	struct iscsi_mgmt_task *mtask;
	struct iscsi_session *session = conn->session;

	
	uint32_t cdgst, rdgst = 0;

	hdr = conn->in.hdr;

	/* verify PDU length */
	conn->in.datalen = ntoh24(hdr->dlength);
	//printf("kiscsi_hdr_recv: hdr->dlength = %d\n", conn->in.datalen);
	if (conn->in.datalen > conn->max_recv_dlength) {
		printf("kiscsi_hdr_recv: iSCSI: datalen %d > %d\n", conn->in.datalen, conn->max_recv_dlength);
		// iscsi_control_cnx_error(conn->handle, ISCSI_ERR_DATALEN);
		//return 0;
	}
	//conn->data_copied = 0;

	/* read AHS */
	conn->in.ahslen = hdr->hlength * (4*sizeof(unsigned short));
	//printf("kiscsi_hdr_recv: conn->in.ahslen = %d\n", hdr->hlength);
	conn->in.offset += conn->in.ahslen;
	conn->in.copy -= conn->in.ahslen;
	
	if (conn->in.copy < 0) 
	{
		printf("kiscsi_hdr_recv: iSCSI: can't handle AHS with length %d bytes\n", conn->in.ahslen);
    printf("kiscsi_hdr_recv:");
    int x = 0;
    for(x=0;x<100;x++)
            printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
    printf("\n");
    //iscsi_control_cnx_error(conn->handle, ISCSI_ERR_AHSLEN);
		return 0;
	}

	/* calculate padding */
	conn->in.padding = conn->in.datalen & (ISCSI_PAD_LEN-1);
	if (conn->in.padding) 
	{
		conn->in.padding = ISCSI_PAD_LEN - conn->in.padding;
		printf("kiscsi_hdr_recv: padding %d bytes !\n", conn->in.padding);
	}

	/*
	if (conn->hdrdgst_en) 
	{
		struct scatterlist sg;

		sg_init_one(&sg, (u8 *)hdr,
			    sizeof(struct iscsi_hdr) + conn->in.ahslen);
		crypto_digest_init(conn->rx_tfm);
		crypto_digest_update(conn->rx_tfm, &sg, 1);
		crypto_digest_final(conn->rx_tfm, (u8 *)&cdgst);
		rdgst = *(uint32_t*)((char*)hdr + sizeof(struct iscsi_hdr) +
				     conn->in.ahslen);
	}*/

	/* save opcode & itt for later */
	conn->in.opcode = hdr->opcode;
	//conn->in.itt = ntohl(hdr->itt);
	conn->in.itt = hdr->itt;
	conn->in.flags = hdr->flags;

	//printf("kiscsi_hdr_recv: hdr->opcode = 0x%x, conn->in.offset = %d, conn->in.copy = %d, conn->in.ahslen = %d, conn->in.datalen = %d\n",  
	//	hdr->opcode, conn->in.offset, conn->in.copy, conn->in.ahslen, conn->in.datalen);

	//if (conn->in.itt < session->cmds_max) 
	//{ 
		/*if (conn->hdrdgst_en && cdgst != rdgst) 
		{
			printk("iSCSI: itt %x: hdrdgst error recv 0x%x "
			       "calc 0x%x\n", conn->in.itt, rdgst, cdgst);
			iscsi_control_cnx_error(conn->handle,
						ISCSI_ERR_HDR_DGST);
			return 0;
		}*/

		//ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
		//conn->in.ctask = ctask;
		//ctask->sc = sc;
		//printf("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);

		//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt];	
			//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];	
		//printf ("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",  conn->in.opcode, conn->id, mtask->itt,  conn->in.datalen);

	//printf("kiscsi_hdr_recv: conn->in.opcode = %d, conn->in.itt = %d\n", conn->in.opcode, conn->in.itt);
	if(conn->in.itt == ISCSI_XMIT_CMDS_MAX)
		printf("kiscsi_hdr_recv: number of CMDs not enough!!!!!!!!!!!\n\n");
		
	switch(conn->in.opcode) 
	{
		
		case ISCSI_OP_SCSI_CMD_RSP:
			ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
			conn->in.ctask = ctask;
			ctask->sc = sc;
			//printf("kiscsi_hdr_recv: rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);

			//if (ctask->in_progress == IN_PROGRESS_READ) {
			if (conn->ctask_in_progress == IN_PROGRESS_READ) {
				if (!conn->in.datalen) 
				{
					rc = iscsi_cmd_rsp(conn, ctask);
					//printf("kiscsi_hdr_recv: rc = iscsi_cmd_rsp = %d\n", rc);
				} 
				else 
				{
					/* got sense or response data;
					 * copying PDU Header to the
					 * connection's header
					 * placeholder */
					memcpy(&conn->hdr, hdr, sizeof(struct iscsi_hdr));
				}
			} 
			//else if (ctask->in_progress == IN_PROGRESS_WRITE) 
			else if (conn->ctask_in_progress == IN_PROGRESS_WRITE) 
			{
				//printf("kiscsi_hdr_recv: Write Response !!!!!!!!!!!!!!!!!!\n");
				rc = iscsi_cmd_rsp(conn, ctask);
				//printf("kiscsi_hdr_recv: rc = iscsi_cmd_rsp = %d\n", rc);
			}
			break;


		case ISCSI_OP_SCSI_DATA_IN:

			ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
			conn->in.ctask = ctask;
			ctask->sc = sc;
			//printf("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);

			/* save flags for non-exceptional status */
			conn->in.flags = hdr->flags;
			/* save cmd_status for sense data */
			conn->in.cmd_status =((struct iscsi_data_rsp*)hdr)->cmd_status;
			rc = iscsi_data_rsp(conn, ctask);
			//printf("kiscsi_hdr_recv: iscsi_data_rsp rc = %d \n", rc);
			break;


		case ISCSI_OP_R2T:
			ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
			conn->in.ctask = ctask;
			ctask->sc = sc;
			
			printf("rsp [op 0x%x cid %d ]\n",  hdr->opcode, conn->id);
			printf("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);
			rc = iscsi_r2t_rsp(conn, ctask);
      break;

    case ISCSI_OP_NOOP_IN:
    //printf("ISCSI_OP_NOOP_IN!!!!!!!!!!!!!!!!\n");
      //Renjs 
      //if (!__send_nopin_rsp(conn, (struct iscsi_nopin*)&hdr, conn->data)) 
     // {
       //       printf("can not send nopin response\n");
     // }
     // else
        //      printf(" send nopin response!\n ");
		case ISCSI_OP_TEXT_RSP:
		case ISCSI_OP_LOGOUT_RSP:
		case ISCSI_OP_ASYNC_EVENT:
		case ISCSI_OP_REJECT:

			mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt];	
			//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];	
			printf ("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",  conn->in.opcode, conn->id, mtask->itt,  conn->in.datalen);

			/* update ExpStatSN */
			//conn->exp_statsn = ntohl(hdr->statsn) + 1;
			conn->exp_statsn = hdr->statsn + 1;
			if (!conn->in.datalen) 
			{
				//struct iscsi_mgmt_task *mtask;
				rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
				//mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];
				if (conn->login_mtask != mtask) 
				{
					//spin_lock(&session->lock);
					//__kfifo_put(session->immpool.queue, (void*)&mtask, sizeof(void*));					
					//spin_unlock(&session->lock);
				}
			}
			break;

		case ISCSI_OP_LOGIN_RSP:
		//case ISCSI_OP_TEXT_RSP:
		
			mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt];	
			//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];	
			printf ("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",  conn->in.opcode, conn->id, mtask->itt,  conn->in.datalen);
		
			if (!conn->in.datalen) 
			{
				rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
				if (conn->login_mtask != mtask) {
					//spin_lock(&session->lock);
					//__kfifo_put(session->immpool.queue, (void*)&mtask, sizeof(void*));
					//spin_unlock(&session->lock);
				}
			}
			break;
		
		case ISCSI_OP_SCSI_TMFUNC_RSP:


			if (conn->in.datalen || conn->in.ahslen) {
				rc = ISCSI_ERR_PROTO;
				break;
			}
			//spin_lock(&session->lock);
			//__kfifo_put(session->immpool.queue, (void*)&mtask,
			//	    sizeof(void*));
			//spin_unlock(&session->lock);
			//del_timer_sync(&conn->tmabort_timer);
			conn->tmabort_state = ((struct iscsi_tm_rsp *)hdr)->response == SCSI_TCP_TM_RESP_COMPLETE ?TMABORT_SUCCESS : TMABORT_FAILED;
			//wake_up(&conn->ehwait);
			break;
		
		default:
			rc = ISCSI_ERR_BAD_OPCODE;
			break;
	}
	//} 


	//else if (conn->in.itt == ISCSI_RESERVED_TAG) 
	//{
	//	if (conn->in.opcode == ISCSI_OP_NOOP_IN &&
	//	    !conn->in.datalen) {
	//		rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
	//	} else {
	//		rc = ISCSI_ERR_BAD_OPCODE;
	//	}
	//} else {
	//	rc = ISCSI_ERR_BAD_ITT;
	//}

	return rc;
}



int
kiscsi_mhdr_recv(struct iscsi_conn *conn )
{
	int rc = 0;
	struct iscsi_hdr *hdr;
	struct iscsi_cmd_task *ctask;
	struct iscsi_mgmt_task *mtask;
	struct iscsi_session *session = conn->session;

	
	uint32_t cdgst, rdgst = 0;

	hdr = conn->in.hdr;

	/* verify PDU length */
	conn->in.datalen = ntoh24(hdr->dlength);
	
	if (conn->in.datalen > conn->max_recv_dlength) {
		printf("iSCSI: datalen %d > %d\n", conn->in.datalen, conn->max_recv_dlength);
		// iscsi_control_cnx_error(conn->handle, ISCSI_ERR_DATALEN);
		return 0;
	}
	conn->data_copied = 0;

	/* read AHS */
	conn->in.ahslen = hdr->hlength*(4*sizeof(unsigned short));
	conn->in.offset += conn->in.ahslen;
	conn->in.copy -= conn->in.ahslen;
	
	if (conn->in.copy < 0) 
	{
		printf("iSCSI: can't handle AHS with length %d bytes\n", conn->in.ahslen);
		//iscsi_control_cnx_error(conn->handle, ISCSI_ERR_AHSLEN);
		return 0;
	}

	/* calculate padding */
	conn->in.padding = conn->in.datalen & (ISCSI_PAD_LEN-1);
	if (conn->in.padding) 
	{
		conn->in.padding = ISCSI_PAD_LEN - conn->in.padding;
		printf("padding %d bytes\n", conn->in.padding);
	}

	/*
	if (conn->hdrdgst_en) 
	{
		struct scatterlist sg;

		sg_init_one(&sg, (u8 *)hdr,
			    sizeof(struct iscsi_hdr) + conn->in.ahslen);
		crypto_digest_init(conn->rx_tfm);
		crypto_digest_update(conn->rx_tfm, &sg, 1);
		crypto_digest_final(conn->rx_tfm, (u8 *)&cdgst);
		rdgst = *(uint32_t*)((char*)hdr + sizeof(struct iscsi_hdr) +
				     conn->in.ahslen);
	}*/

	/* save opcode & itt for later */
	conn->in.opcode = hdr->opcode;
	//conn->in.itt = ntohl(hdr->itt);
	conn->in.itt = hdr->itt;

	//printf("kiscsi_hdr_recv: hdr->opcode = 0x%x, conn->in.offset = %d, conn->in.copy = %d, conn->in.ahslen = %d, conn->in.datalen = %d\n",  
	//	hdr->opcode, conn->in.offset, conn->in.copy, conn->in.ahslen, conn->in.datalen);

	//if (conn->in.itt < session->cmds_max) 
	//{ 
		/*if (conn->hdrdgst_en && cdgst != rdgst) 
		{
			printk("iSCSI: itt %x: hdrdgst error recv 0x%x "
			       "calc 0x%x\n", conn->in.itt, rdgst, cdgst);
			iscsi_control_cnx_error(conn->handle,
						ISCSI_ERR_HDR_DGST);
			return 0;
		}*/

		//ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
		//conn->in.ctask = ctask;
		//ctask->sc = sc;
		//printf("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);

		//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt];	
			//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];	
		//printf ("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",  conn->in.opcode, conn->id, mtask->itt,  conn->in.datalen);

	//printf("kiscsi_hdr_recv: conn->in.opcode = %d, conn->in.itt = %d\n", conn->in.opcode, conn->in.itt);
	if(conn->in.itt == ISCSI_XMIT_CMDS_MAX)
		printf("kiscsi_hdr_recv: number of CMDs not enough!!!!!!!!!!!\n\n");
		
	switch(conn->in.opcode) 
	{
		
		case ISCSI_OP_SCSI_CMD_RSP:
			printf("kiscsi_mhdr_recv: invalid in ISCSI_OP_SCSI_CMD_RSP !!!!!\n");
			ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
			conn->in.ctask = ctask;
			//ctask->sc = sc;
			//printf("kiscsi_hdr_recv: rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);

			//if (ctask->in_progress == IN_PROGRESS_READ) {
			if (conn->ctask_in_progress == IN_PROGRESS_READ) {
				if (!conn->in.datalen) 
				{
					rc = iscsi_cmd_rsp(conn, ctask);
				} 
				else 
				{
					/* got sense or response data;
					 * copying PDU Header to the
					 * connection's header
					 * placeholder */
					memcpy(&conn->hdr, hdr, sizeof(struct iscsi_hdr));
				}
			} 
			//else if (ctask->in_progress == IN_PROGRESS_WRITE) 
			else if (conn->ctask_in_progress == IN_PROGRESS_WRITE) 
			{
				//printf("kiscsi_hdr_recv: Write Response !!!!!!!!!!!!!!!!!!\n");
				rc = iscsi_cmd_rsp(conn, ctask);
			}
			break;


		case ISCSI_OP_SCSI_DATA_IN:
			printf("kiscsi_mhdr_recv: invalid in ISCSI_OP_SCSI_DATA_IN !!!!!\n");
			ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
			conn->in.ctask = ctask;
			//ctask->sc = sc;
			//printf("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);

			/* save flags for non-exceptional status */
			conn->in.flags = hdr->flags;
			/* save cmd_status for sense data */
			conn->in.cmd_status =((struct iscsi_data_rsp*)hdr)->cmd_status;
			rc = iscsi_data_rsp(conn, ctask);
			//printf("kiscsi_hdr_recv: iscsi_data_rsp rc = %d \n", rc);
			break;


		case ISCSI_OP_R2T:
			printf("kiscsi_mhdr_recv: invalid in ISCSI_OP_R2T !!!!!\n");
			ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
			conn->in.ctask = ctask;
			//ctask->sc = sc;
			
			printf("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);
			rc = iscsi_r2t_rsp(conn, ctask);
			break;

		case ISCSI_OP_NOOP_IN:
		case ISCSI_OP_TEXT_RSP:
		case ISCSI_OP_LOGOUT_RSP:
		case ISCSI_OP_ASYNC_EVENT:
		case ISCSI_OP_REJECT:

			mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt];	
			//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];	
			printf ("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",  conn->in.opcode, conn->id, mtask->itt,  conn->in.datalen);

			/* update ExpStatSN */
			//conn->exp_statsn = ntohl(hdr->statsn) + 1;
			conn->exp_statsn = hdr->statsn + 1;
			if (!conn->in.datalen) 
			{
				//struct iscsi_mgmt_task *mtask;
				rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
				//mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];
				if (conn->login_mtask != mtask) 
				{
					//spin_lock(&session->lock);
					//__kfifo_put(session->immpool.queue, (void*)&mtask, sizeof(void*));					
					//spin_unlock(&session->lock);
				}
			}
			break;

		case ISCSI_OP_LOGIN_RSP:
		//case ISCSI_OP_TEXT_RSP:
		
			mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt];	
			//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];	
			printf ("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",  conn->in.opcode, conn->id, mtask->itt,  conn->in.datalen);
		
			if (!conn->in.datalen) 
			{
				rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
				if (conn->login_mtask != mtask) {
					//spin_lock(&session->lock);
					//__kfifo_put(session->immpool.queue, (void*)&mtask, sizeof(void*));
					//spin_unlock(&session->lock);
				}
			}
			break;
		
		case ISCSI_OP_SCSI_TMFUNC_RSP:


			if (conn->in.datalen || conn->in.ahslen) {
				rc = ISCSI_ERR_PROTO;
				break;
			}
			//spin_lock(&session->lock);
			//__kfifo_put(session->immpool.queue, (void*)&mtask,
			//	    sizeof(void*));
			//spin_unlock(&session->lock);
			//del_timer_sync(&conn->tmabort_timer);
			conn->tmabort_state = ((struct iscsi_tm_rsp *)hdr)->response == SCSI_TCP_TM_RESP_COMPLETE ?TMABORT_SUCCESS : TMABORT_FAILED;
			//wake_up(&conn->ehwait);
			break;
		
		default:
			rc = ISCSI_ERR_BAD_OPCODE;
			break;
	}
	//} 


	//else if (conn->in.itt == ISCSI_RESERVED_TAG) 
	//{
	//	if (conn->in.opcode == ISCSI_OP_NOOP_IN &&
	//	    !conn->in.datalen) {
	//		rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
	//	} else {
	//		rc = ISCSI_ERR_BAD_OPCODE;
	//	}
	//} else {
	//	rc = ISCSI_ERR_BAD_ITT;
	//}

	return rc;
}



#ifdef MHDR
int
kiscsi_mhdr_recv(struct iscsi_conn *conn)
{
	int rc = 0;
	struct iscsi_hdr *hdr;
	struct iscsi_cmd_task *ctask;
	struct iscsi_session *session = conn->session;

	
	uint32_t cdgst, rdgst = 0;

	hdr = conn->in.hdr;

	/* verify PDU length */
	conn->in.datalen = ntoh24(hdr->dlength);
	
	if (conn->in.datalen > conn->max_recv_dlength) {
		printf("iSCSI: datalen %d > %d\n", conn->in.datalen, conn->max_recv_dlength);
		// iscsi_control_cnx_error(conn->handle, ISCSI_ERR_DATALEN);
		return 0;
	}
	conn->data_copied = 0;

	/* read AHS */
	conn->in.ahslen = hdr->hlength*(4*sizeof(unsigned short));
	conn->in.offset += conn->in.ahslen;
	conn->in.copy -= conn->in.ahslen;
	
	if (conn->in.copy < 0) 
	{
		printf("iSCSI: can't handle AHS with length %d bytes\n", conn->in.ahslen);
		//iscsi_control_cnx_error(conn->handle, ISCSI_ERR_AHSLEN);
		return 0;
	}

	/* calculate padding */
	conn->in.padding = conn->in.datalen & (ISCSI_PAD_LEN-1);
	if (conn->in.padding) 
	{
		conn->in.padding = ISCSI_PAD_LEN - conn->in.padding;
		printf("padding %d bytes\n", conn->in.padding);
	}

	/*
	if (conn->hdrdgst_en) 
	{
		struct scatterlist sg;

		sg_init_one(&sg, (u8 *)hdr,
			    sizeof(struct iscsi_hdr) + conn->in.ahslen);
		crypto_digest_init(conn->rx_tfm);
		crypto_digest_update(conn->rx_tfm, &sg, 1);
		crypto_digest_final(conn->rx_tfm, (u8 *)&cdgst);
		rdgst = *(uint32_t*)((char*)hdr + sizeof(struct iscsi_hdr) +
				     conn->in.ahslen);
	}*/

	/* save opcode & itt for later */
	conn->in.opcode = hdr->opcode;
	//conn->in.itt = ntohl(hdr->itt);
	conn->in.itt = hdr->itt;

	printf("opcode 0x%x offset %d copy %d ahslen %d datalen %d\n",  hdr->opcode, conn->in.offset, conn->in.copy, conn->in.ahslen, conn->in.datalen);

	//if (conn->in.itt < session->cmds_max) 
	//{ 
		/*if (conn->hdrdgst_en && cdgst != rdgst) 
		{
			printk("iSCSI: itt %x: hdrdgst error recv 0x%x "
			       "calc 0x%x\n", conn->in.itt, rdgst, cdgst);
			iscsi_control_cnx_error(conn->handle,
						ISCSI_ERR_HDR_DGST);
			return 0;
		}*/

		ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
		conn->in.ctask = ctask;
		//ctask->sc = sc;
		printf("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",  hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,  conn->in.datalen);

		struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt];	
		//struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];	
		printf ("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",  conn->in.opcode, conn->id, mtask->itt,  conn->in.datalen);


		switch(conn->in.opcode) 
		{
		case ISCSI_OP_SCSI_CMD_RSP:

			if (ctask->in_progress == IN_PROGRESS_READ) {
				if (!conn->in.datalen) 
				{
					rc = iscsi_cmd_rsp(conn, ctask);
				} 
				else 
				{
					/* got sense or response data;
					 * copying PDU Header to the
					 * connection's header
					 * placeholder */
					memcpy(&conn->hdr, hdr, sizeof(struct iscsi_hdr));
				}
			} 
			else if (ctask->in_progress == IN_PROGRESS_WRITE) 
			{
				rc = iscsi_cmd_rsp(conn, ctask);
			}
			break;

		case ISCSI_OP_SCSI_DATA_IN:
			/* save flags for non-exceptional status */
			conn->in.flags = hdr->flags;
			/* save cmd_status for sense data */
			conn->in.cmd_status =((struct iscsi_data_rsp*)hdr)->cmd_status;
			rc = iscsi_data_rsp(conn, ctask);
			printf("kiscsi_hdr_recv: iscsi_data_rsp rc = %d \n", rc);
			break;

		case ISCSI_OP_R2T:
			rc = iscsi_r2t_rsp(conn, ctask);
			break;

		case ISCSI_OP_NOOP_IN:
		case ISCSI_OP_TEXT_RSP:
		case ISCSI_OP_LOGOUT_RSP:
		case ISCSI_OP_ASYNC_EVENT:
		case ISCSI_OP_REJECT:
			/* update ExpStatSN */
			//conn->exp_statsn = ntohl(hdr->statsn) + 1;
			conn->exp_statsn = hdr->statsn + 1;
			if (!conn->in.datalen) 
			{
				struct iscsi_mgmt_task *mtask;
				rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
				mtask = (struct iscsi_mgmt_task *)session->imm_cmds[conn->in.itt -ISCSI_IMM_ITT_OFFSET];
				if (conn->login_mtask != mtask) 
				{
					//spin_lock(&session->lock);
					//__kfifo_put(session->immpool.queue, (void*)&mtask, sizeof(void*));					
					//spin_unlock(&session->lock);
				}
			}
			break;

		case ISCSI_OP_LOGIN_RSP:
		//case ISCSI_OP_TEXT_RSP:
			if (!conn->in.datalen) 
			{
				rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
				if (conn->login_mtask != mtask) {
					//spin_lock(&session->lock);
					//__kfifo_put(session->immpool.queue, (void*)&mtask, sizeof(void*));
					//spin_unlock(&session->lock);
				}
			}
			break;
		
		case ISCSI_OP_SCSI_TMFUNC_RSP:
			if (conn->in.datalen || conn->in.ahslen) {
				rc = ISCSI_ERR_PROTO;
				break;
			}
			//spin_lock(&session->lock);
			//__kfifo_put(session->immpool.queue, (void*)&mtask,
			//	    sizeof(void*));
			//spin_unlock(&session->lock);
			//del_timer_sync(&conn->tmabort_timer);
			conn->tmabort_state = ((struct iscsi_tm_rsp *)hdr)->response == SCSI_TCP_TM_RESP_COMPLETE ?TMABORT_SUCCESS : TMABORT_FAILED;
			//wake_up(&conn->ehwait);
			break;
		
		default:
			rc = ISCSI_ERR_BAD_OPCODE;
			break;
		}
	//} 


	//else if (conn->in.itt == ISCSI_RESERVED_TAG) 
	//{
	//	if (conn->in.opcode == ISCSI_OP_NOOP_IN &&
	//	    !conn->in.datalen) {
	//		rc = iscsi_control_recv_pdu(conn->handle, hdr, NULL, 0);
	//	} else {
	//		rc = ISCSI_ERR_BAD_OPCODE;
	//	}
	//} else {
	//	rc = ISCSI_ERR_BAD_ITT;
	//}

	return rc;
}
#endif



/*
 * iscsi_ctask_copy - copy skb bits to the destanation cmd task
 *
 * The function calls skb_copy_bits() and updates per-connection and
 * per-cmd byte counters.
 */
static inline int
 iscsi_ctask_copy(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask, void *buf, int buf_size)
{
	//printf("iscsi_ctask_copy: 1 \n");
	//printf("iscsi_ctask_copy: iscsi_ctask_copy entering,  sc->request_bufflen=buf_size=%d, conn->data_copied = %d \n", buf_size, conn->data_copied);
	int buf_left = buf_size - conn->data_copied;
	//int size = min(conn->in.copy, buf_left);
	//int rc;
	//size = min(size, ctask->data_count);
	int size;

	if(conn->recv_data_again == 0)
		size= min((conn->in.len - 48), buf_left);
	if(conn->recv_data_again == 1)
		size= min(conn->in.copy, buf_left);

	/*
	 * Read counters (in bytes):
	 *
	 *	conn->in.offset		offset within in progress SKB
	 *	conn->in.copy		left to copy from in progress SKB
	 *				including padding
	 *	conn->in.copied		copied already from in progress SKB
	 *	conn->data_copied	copied already from in progress buffer
	 *	ctask->sent		total bytes sent up to the MidLayer
	 *	ctask->data_count	left to copy from in progress Data-In
	 *	buf_left		left to copy from in progress buffer
	 */
	//printf(" iscsi_ctask_copy[1]: size = %d, conn->data_copied = %d, conn->in.offset = %d \n", size, conn->data_copied, conn->in.offset);
	//rc = skb_copy_bits(conn->in.skb, conn->in.offset, (char*)buf + conn->data_copied, size);
	if(ctask->sc->app_work == 0)
		memcpy((char*)buf + conn->data_copied, conn->in.iscsi_skb+ conn->in.offset, size);
	/*else
	{
		int data_to_copy = 0;
		int copied = 0;
		data_list_t * data_head = (data_list_t *) buf;
		while(1)
		{
			if(data_head == NULL)
				break;
			data_to_copy = data_head->data_len - data_head->copied;
			if(data_to_copy > size - copied)
				data_to_copy = size - copied;
			memcpy( ((char*)cvmx_phys_to_ptr(data_head->data_ptr)) + data_head->offset + data_head->copied + conn->data_copied, conn->in.iscsi_skb + conn->in.offset + copied, data_to_copy);
			copied += data_to_copy;
			data_head->copied += data_to_copy;
			if(copied < size && data_head->copied == data_head->data_len)
				data_head = data_head->next;
			if(copied == size)
				break;
		}	
	}*/


	// must fit into skb->len 
	//BUG_ON(rc);

	conn->in.offset += size;
	conn->in.copy -= size;
	conn->in.copied += size;
	conn->data_copied += size;
	
	ctask->sent += size;
	ctask->data_count -= size;

	//printf(" iscsi_ctask_copy[2]: size = %d, conn->data_copied = %d, conn->in.offset = %d \n", size, conn->data_copied, conn->in.offset);


	//BUG_ON(conn->in.copy < 0);
	//BUG_ON(ctask->data_count < 0);

	//if (buf_size != conn->data_copied) {
	//	if (!ctask->data_count) {
	//		//BUG_ON(buf_size - conn->data_copied < 0);
	//		// done with this PDU 
	//		return buf_size - conn->data_copied;
	//	}
	//	return -EAGAIN;
	//}

	/*int i=0;
	printf("\niscsi_ctask_copy: sc->request_buffer = ");
	for(i=0; i<size; i++)
	{
		printf("%x ", ((char *)buf)[i]);
	}
	printf("\n");*/
	//printf("iscsi_ctask_copy: sc->request_bufflen = %d\n", buf_size);

	// done with this buffer or with both - PDU and buffer 
	//conn->data_copied = 0;
	return 0;
}









/*
 * iscsi_tcp_copy - copy skb bits to the destanation buffer
 *
 * The function calls skb_copy_bits() and updates per-connection byte counters.
 */
static inline int
kiscsi_tcp_copy(struct iscsi_conn *conn, void *buf, int buf_size)
{
	int buf_left = buf_size - conn->data_copied;
	int size = min(conn->in.copy, buf_left);
	int rc;

	//debug_tcp("tcp_copy %d bytes at offset %d copied %d\n",
	//       size, conn->in.offset, conn->data_copied);
	//BUG_ON(size <= 0);

	//rc = skb_copy_bits(conn->in.skb, conn->in.offset, (char*)buf + conn->data_copied, size);
	memcpy((char*)buf + conn->data_copied, conn->in.iscsi_skb+ conn->in.offset, size);

	//BUG_ON(rc);
	conn->in.offset += size;
	conn->in.copy -= size;
	conn->in.copied += size;
	conn->data_copied += size;

	if (buf_size != conn->data_copied)
		return -EAGAIN;

	return 0;
}










int kiscsi_mdata_recv(struct iscsi_conn *conn)
{	
	//printf("kiscsi_data_recv: 1 \n\n");
	struct iscsi_session *session = conn->session;
	int rc = 0;

	switch(conn->in.opcode) 
	{

	case ISCSI_OP_SCSI_DATA_IN: 
	{
	    struct iscsi_cmd_task *ctask = conn->in.ctask;
	    struct scsi_cmnd *sc = ctask->sc;

		
	    //BUG_ON(!(ctask->in_progress & IN_PROGRESS_READ &&
		//     conn->in_progress == IN_PROGRESS_DATA_RECV));
	    //BUG_ON(ctask != (void*)sc->SCp.ptr);

	    /*
	     * copying Data-In into the Scsi_Cmnd
	     */
	   //  printf("kiscsi_data_recv: 2 \n\n");
	   //if (sc->use_sg)
	    //{
	    /*
		int i;
		struct scatterlist *sg = sc->request_buffer;

		for (i = ctask->sg_count; i < sc->use_sg; i++) {
			char *dest;

			dest = kmap_atomic(sg[i].page, KM_USER0);

			rc = iscsi_ctask_copy(conn, ctask, dest + sg[i].offset,
					      sg->length);

			kunmap_atomic(dest, KM_USER0);
			if (rc == -EAGAIN) {
				// continue with the next SKB/PDU 
				goto exit;
			}
			if (!rc) {
				ctask->sg_count++;
			}
			if (!ctask->data_count) {
				rc = 0;
				break;
			}
			if (!conn->in.copy) {
				rc = -EAGAIN;
				goto exit;
			}
		}*/
	  //	printf("kiscsi_data_recv: SCSI using sg!! \n");
	  //  } 
	    //else 
	    //{
	//	printf("kiscsi_data_recv: 3 \n\n");
	   
		if(conn == NULL)
	   		printf("kiscsi_data_recv:  conn = NULL\n");
		if(ctask == NULL)
	   		printf("kiscsi_data_recv:  ctask = NULL\n");

	//	printf("kiscsi_data_recv: 4 \n\n");

		if(sc == NULL)
	   		printf("kiscsi_data_recv:  sc = NULL\n");

	//	printf("kiscsi_data_recv: 5 \n\n");

		if(sc->request_buffer == NULL)
	   		printf("kiscsi_data_recv:  sc->request_buffer = NULL\n");

	//	printf("kiscsi_data_recv: 6 \n\n");
	   
		//printf("kiscsi_data_recv:  sc->request_bufflen = %d \n", sc->request_bufflen);
	   
	    rc = iscsi_ctask_copy(conn, ctask, sc->request_buffer, sc->request_bufflen);
		if (rc == -EAGAIN)
			goto exit;
		rc = 0;
	   // }

		
	    /* check for non-exceptional status */
	    if (conn->in.flags & ISCSI_FLAG_DATA_STATUS)
	    {
		   // printf("kiscsi_data_recv: done [sc %lx res %d itt 0x%x]\n", (long)sc, sc->result, ctask->itt);
		    iscsi_ctask_cleanup(conn, ctask);
		    sc->result = conn->in.cmd_status;
		    sc->scsi_done(sc);
	    }
	    else
	    {
	    	//printf("kiscsi_data_recv: agian !\n");
	    }

	}
	break;

	case ISCSI_OP_SCSI_CMD_RSP:{
		/*
		 * SCSI Sense Data:
		 * copying the entire Data Segment.
		 */

		if (kiscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}
		/*
		 * check for sense
		 */
		conn->in.hdr = &conn->hdr;
		rc = iscsi_cmd_rsp(conn, conn->in.ctask);
		//printf("kiscsi_data_recv: rc = iscsi_cmd_rsp = %d\n", rc);
	}
	break;

	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_LOGIN_RSP:
	case ISCSI_OP_NOOP_IN: {
		struct iscsi_mgmt_task *mtask = NULL;

		if (conn->in.itt != ISCSI_RESERVED_TAG) {
			mtask = (struct iscsi_mgmt_task *)
				session->imm_cmds[conn->in.itt -
					ISCSI_IMM_ITT_OFFSET];
		}

		/*
		 * Collect data segment to the connection's data
		 * placeholder
		 */
		if (kiscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}

		rc = iscsi_control_recv_pdu(conn->handle, conn->in.hdr, conn->data, conn->in.datalen);

		if (mtask && conn->login_mtask != mtask) {
			//spin_lock(&session->lock);
			//__kfifo_put(session->immpool.queue, (void*)&mtask,
			//	    sizeof(void*));
			//spin_unlock(&session->lock);
		}
	}
	break;

	default:
		//BUG_ON(1);
		break;
	}
exit:
	return rc;
}




int kiscsi_data_recv(struct iscsi_conn *conn)
{	
	//printf("kiscsi_data_recv: 1 \n\n");
	struct iscsi_session *session = conn->session;
	int rc = 0;

	switch(conn->in.opcode) 
	{

	case ISCSI_OP_SCSI_DATA_IN: 
	{
	    struct iscsi_cmd_task *ctask = conn->in.ctask;
	    struct scsi_cmnd *sc = ctask->sc;

		
	    //BUG_ON(!(ctask->in_progress & IN_PROGRESS_READ &&
		//     conn->in_progress == IN_PROGRESS_DATA_RECV));
	    //BUG_ON(ctask != (void*)sc->SCp.ptr);

	    /*
	     * copying Data-In into the Scsi_Cmnd
	     */
	   //  printf("kiscsi_data_recv: 2 \n\n");
	   //if (sc->use_sg)
	    //{
	    /*
		int i;
		struct scatterlist *sg = sc->request_buffer;

		for (i = ctask->sg_count; i < sc->use_sg; i++) {
			char *dest;

			dest = kmap_atomic(sg[i].page, KM_USER0);

			rc = iscsi_ctask_copy(conn, ctask, dest + sg[i].offset,
					      sg->length);

			kunmap_atomic(dest, KM_USER0);
			if (rc == -EAGAIN) {
				// continue with the next SKB/PDU 
				goto exit;
			}
			if (!rc) {
				ctask->sg_count++;
			}
			if (!ctask->data_count) {
				rc = 0;
				break;
			}
			if (!conn->in.copy) {
				rc = -EAGAIN;
				goto exit;
			}
		}*/
	  //	printf("kiscsi_data_recv: SCSI using sg!! \n");
	  //  } 
	    //else 
	    //{
	//	printf("kiscsi_data_recv: 3 \n\n");
	   
		if(conn == NULL)
	   		printf("kiscsi_data_recv:  conn = NULL\n");
		if(ctask == NULL)
	   		printf("kiscsi_data_recv:  ctask = NULL\n");

	//	printf("kiscsi_data_recv: 4 \n\n");

		if(sc == NULL)
	   		printf("kiscsi_data_recv:  sc = NULL\n");

	//	printf("kiscsi_data_recv: 5 \n\n");

		if(sc->request_buffer == NULL)
	   		printf("kiscsi_data_recv:  sc->request_buffer = NULL\n");

	//	printf("kiscsi_data_recv: 6 \n\n");
	   
		//printf("kiscsi_data_recv:  sc->request_bufflen = %d \n", sc->request_bufflen);
	   
	    rc = iscsi_ctask_copy(conn, ctask, sc->request_buffer, sc->request_bufflen);
		if (rc == -EAGAIN)
			goto exit;
		rc = 0;
	   // }

		
	    /* check for non-exceptional status */
	    if ((conn->in.flags & ISCSI_FLAG_DATA_STATUS) && (conn->in.total_len - 48 == conn->in.datalen))
	    {
		   // printf("kiscsi_data_recv: done [sc %lx res %d itt 0x%x]\n", (long)sc, sc->result, ctask->itt);
		    iscsi_ctask_cleanup(conn, ctask);
		    sc->result = conn->in.cmd_status;
		    sc->scsi_done(sc);
	    }
	    else
	    {
	    	//printf("kiscsi_data_recv: agian !\n");
	    }

	}
	break;

	case ISCSI_OP_SCSI_CMD_RSP:{
		/*
		 * SCSI Sense Data:
		 * copying the entire Data Segment.
		 */

		if (kiscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}
		/*
		 * check for sense
		 */
		conn->in.hdr = &conn->hdr;
		rc = iscsi_cmd_rsp(conn, conn->in.ctask);
		//printf("kiscsi_data_recv: rc = iscsi_cmd_rsp = %d\n", rc);
	}
	break;

	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_LOGIN_RSP:
	case ISCSI_OP_NOOP_IN: {
		struct iscsi_mgmt_task *mtask = NULL;

		if (conn->in.itt != ISCSI_RESERVED_TAG) {
			mtask = (struct iscsi_mgmt_task *)
				session->imm_cmds[conn->in.itt -
					ISCSI_IMM_ITT_OFFSET];
		}

		/*
		 * Collect data segment to the connection's data
		 * placeholder
		 */
		if (kiscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}

		rc = iscsi_control_recv_pdu(conn->handle, conn->in.hdr, conn->data, conn->in.datalen);

		if (mtask && conn->login_mtask != mtask) {
			//spin_lock(&session->lock);
			//__kfifo_put(session->immpool.queue, (void*)&mtask,
			//	    sizeof(void*));
			//spin_unlock(&session->lock);
		}
	}
	break;

	default:
		//BUG_ON(1);
		break;
	}
exit:
	return rc;
}



/*
 * TCP receive
 */
//static int iscsi_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb, unsigned int offset, size_t len)
 int kiscsi_tcp_recv(iscsi_cnx_h cnxh)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	int socket = conn->socket;
	printf("[kiscsi_tcp_recv]socket id is %d\n", socket);
	int res;
	//int res = cvm_so_recv(socket, conn->in.iscsi_skb, 8192, 0);

	do
	{
		res = cvm_so_recv(socket, conn->in.iscsi_skb, 8192, 0);
		
	}while(res <= 0);
	
	int rc;
	//struct iscsi_conn *conn = iscsi_conn_get(rd_desc);
	//int start = skb_headlen(skb);

	/*
	 * Save current SKB and its offset in the corresponding
	 * connection context.
	 */
	//conn->in.copy = start - offset;
	conn->in.copy = res;
	conn->in.offset = 0;
	//conn->in.skb = skb;
	//conn->in.len = conn->in.copy;
	conn->in.len = res;
	//BUG_ON(conn->in.copy <= 0);
	//printf ("kiscsi_tcp_recv: in %d bytes\n", conn->in.copy);
	// ¥Ú”°
	
	printf("tcp_data_recv = 0x ");
	int x = 0;
	for(x=0;x<res;x++)
		printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
	printf("\n");

	
more:
	conn->in.copied = 0;
	rc = 0;

	if (conn->in_progress == IN_PROGRESS_WAIT_HEADER || conn->in_progress == IN_PROGRESS_HEADER_GATHER)
	{
		// ≥È»°Õ∑≤ø–≈œ¢
		rc = kiscsi_mhdr_extract(conn);  
		if (rc == -EAGAIN)
			goto nomore;
		/*
		 * Verify and process incoming PDU header.
		 */
		rc = kiscsi_mhdr_recv(conn);  // ≥…π¶∑µªÿ0

		//printf("kiscsi_tcp_recv: hdr_recv  rc = %d, conn->in.datalen = %d, conn->in.copy = %d \n", rc, conn->in.datalen, conn->in.copy);
		
		if (!rc && conn->in.datalen)
		{
			conn->in_progress = IN_PROGRESS_DATA_RECV;
			printf("kiscsi_tcp_recv: hdr_recv succeed !\n");
		} 
		else if (rc) 
		{
			printf("iSCSI: bad hdr rc (%d) \n", rc);
			//iscsi_control_cnx_error(conn->handle, rc);
			return 0;
		}

	}


	if (conn->in_progress == IN_PROGRESS_DATA_RECV && conn->in.copy) 
	{

		//debug_tcp("data_recv offset %d copy %d\n",  conn->in.offset, conn->in.copy);
		//printf ("kiscsi_tcp_recv: data_recv offset %d copy %d\n",  conn->in.offset, conn->in.copy);
		
		rc =kiscsi_mdata_recv(conn);
		if (rc) 
		{
			if (rc == -EAGAIN) 
			{
				//rd_desc->count = conn->in.datalen -conn->in.ctask->sent;
				goto again;
			}
			printf("iSCSI: bad data rc (%d)\n", rc);
			//iscsi_control_cnx_error(conn->handle, rc);
			return 0;
		}
		
		printf("kiscsi_tcp_recv: change  conn->in_progress = IN_PROGRESS_WAIT_HEADER  kiscsi_data_recv done ! rc = %d\n", rc);
		conn->in.copy -= conn->in.padding;
		conn->in.offset += conn->in.padding;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
		//printf("kiscsi_tcp_recv: 88888888888888888888888888888888888 \n\n\n\n\n");
	}

	//debug_tcp("f, processed %d from out of %d padding %d\n",
	//       conn->in.offset - offset, len, conn->in.padding);
	//BUG_ON(conn->in.offset - offset > len);

	//if (conn->in.offset - offset != len) {
	//	debug_tcp("continue to process %d bytes\n",
	//	       len - (conn->in.offset - offset));		
	//	goto more;
	//}
	
	//if (conn->in.offset -0 != len) {
	//	printf("continue to process %d bytes\n", len - (conn->in.offset -0));		
	//	goto more;
	//}

nomore:
	//BUG_ON(conn->in.offset - offset == 0);
	return conn->in.offset ;

again:
	//debug_tcp("c, processed %d from out of %d rd_desc_cnt %d\n", conn->in.offset - offset, len, rd_desc->count);
	//BUG_ON(conn->in.offset - offset == 0);
	//BUG_ON(conn->in.offset - offset > len);

	return conn->in.offset;
}









/*
 * TCP receive
 */
//static int iscsi_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb, unsigned int offset, size_t len)
 int kiscsi_tcp_data_recv(struct iscsi_conn *conn, struct scsi_cmnd *sc )
{
 // printf("kiscsi_tcp_data_recv   enter\n");
	if(conn->hdr_size != 48)
		printf("conn->hdr_size is %d\n", conn->hdr_size);
	//printf("\nkiscsi_tcp_data_recv: entering! \n");
	//printf("hdr itt is %d\n", conn->in.hdr->itt);

	int continu = 0;
	conn->recv_data_again = 0;
	
	int socket = conn->socket;
	int res;
	int rc;
	int x=0;
	conn->data_copied = 0;

AA:
	if(conn->in_progress == IN_PROGRESS_WAIT_HEADER)
	{
		//res = cvm_so_recv(socket, conn->in.iscsi_skb, conn->hdr_size, 0);
		res = cvm_so_recv(socket, conn->in.iscsi_skb, 48, 0);
	}
	else
		printf("++++++++++++++++++++++++++1,	conn->in_progress is %d\n", conn->in_progress);
	if(res <= 0)
	{
		if(res < -1)
			printf("======================:%d\n", res);
		return res;
	}
		
	if(res != 48)
	{
		do
		{
			int temp_rc = cvm_so_recv(socket, conn->in.iscsi_skb + res, 48 - res, 0);
			if(temp_rc > 0)
				res += temp_rc;
		}
		while(res < 48);
		/*while(1)
		{
		printf("++++++++++++++++++++++++++2\n");
		printf("kiscsi_tcp_data_recv: [1]tcp_data_recv = 0x ");
		x = 0;
		for(x=0;x<res;x++)
		printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
		printf("\n");
		res = cvm_so_recv(socket, conn->in.iscsi_skb, 48, 0);
		}*/
		//printf("kiscsi_tcp_data_recv: [1]tcp_data_recv = 0x ");
                //x = 0;                
                //for(x=0;x<res;x++)    
                //printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
                //printf("\n");         
                //res = cvm_so_recv(socket, conn->in.iscsi_skb, 48, 0);
	}
  //printf("kiscsi_tcp_data_recv   afer recv head\n");
//	if((unsigned char *)conn->in.iscsi_skb[0] == 0x20 )
	//	printf("NOOPIN 1\n");
	
	conn->in.copy = res;
	conn->in.offset = 0;
	conn->in.len = res;
	conn->in.total_len +=res;
	
	//printf("kiscsi_tcp_data_recv: [1]tcp_data_recv = 0x ");
	//x = 0;
	//for(x=0;x<res;x++)
	//printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
	//printf("\n");


	
more:
	
	conn->in.copied = 0;
	rc = 0;
	//printf ("kiscsi_tcp_data_recv[2]: in %d bytes, offset = %d \n", conn->in.len, conn->in.offset);
	//printf("conn->in_progress is %d\n", conn->in_progress);
	
	if (conn->in_progress == IN_PROGRESS_WAIT_HEADER || conn->in_progress == IN_PROGRESS_HEADER_GATHER)
	{
	
          // ≥È»°Õ∑≤ø–≈œ¢
          rc = kiscsi_hdr_extract(conn);
         // printf(" after rc = kiscsi_hdr_extract(conn);  \n");
          //Renjs
          /*
          if(conn->hdr.opcode == 0x20 )
          {
                  if (!__send_nopin_rsp(conn, (struct iscsi_nopin*)&(conn->hdr), conn->data)) 
                  {
                          printf("can not send nopin response\n");
                  }
                  else
                  printf(" fopin response!\n ");
                  } 
           */
          //printf("!!!!!!after kiscsi_hdr_extract opcode = 0x%x\n ",conn->in.hdr->opcode);
          //printf("!!!!!!after kiscsi_hdr_extract itt = 0x%x\n ",conn->in.hdr->itt);
          //printf("!!!!!!after kiscsi_hdr_extract ttt = 0x%x\n ",conn->in.hdr->ttt);
          //printf("!!!!!!after kiscsi_hdr_extract statsn = 0x%x\n ",conn->in.hdr->statsn);
          //printf("!!!!!!after kiscsi_hdr_extract exp_statsn = 0x%x\n ",conn->in.hdr->exp_statsn);
          if((unsigned char *)conn->in.iscsi_skb[0] == 0x20);
          {
         // printf("nopin \n");
          int i;
          struct iscsi_hdr hdr_nopout;
          memset(&hdr_nopout, 0, sizeof(struct iscsi_cmd));
          hdr_nopout.opcode = 0x40;
          hdr_nopout.itt = 0xffffffff;
          hdr_nopout.ttt = conn->in.hdr->ttt;
          hdr_nopout.statsn = conn->in.hdr->exp_statsn;
          for(i = 0; i <= 7; i++)
                  hdr_nopout.lun[i] = conn->in.hdr->lun[i];
          int ret, total = 0;

          while (total != 48)
          {
                  ret = cvm_so_send (conn->socket, ((uint8_t *)&hdr_nopout) - total, 48 - total, 0);
                  if(ret >= 0)
                  { 
                          total += ret;
                          //printf("nopout total is %d\n",total);
                  }

          }
    //        return 0;
          }
		//printf("kiscsi_tcp_data_recv: [hdr_extract]  rc = %d\n", rc );
		if (rc == -EAGAIN)
		{
			printf("rc == -EAGAIN\n");
			goto nomore;
		}

 //Renjs   for writing
              if(sc == NULL && conn->hdr.opcode == 0x21 && conn->hdr.flags == 0x80)
			  	return 0;


		if(sc == NULL)
		{
			//Renjs –Ëº”»Îerror¥¶¿Ì∑Ω Ω
			struct iscsi_hdr * hdr;
			struct itt_work * work;
			hdr = conn->in.hdr;
			if(hdr->itt == 0xffffffff) //NOOP_IN
			{
				/*res = cvm_so_recv(socket, conn->in.iscsi_skb, 8192, 0);
				if(res > 0)
				{
					printf("NOOP_IN = 0x ");
                                        x = 0;
                                        for(x=0;x<res;x++)
                                        printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
                                        printf("\n");
				}*/
				printf("NOOPIN 2\n");
				return 0;
				sc = NULL;
				work = NULL;
			}
			else if(hdr->itt > ITTLENGTH)
			{
				printf("hdr->itt > ITTLENGTH,	%d\n", hdr->itt);
				//printf("kiscsi_tcp_data_recv: [1]tcp_data_recv = 0x ");
				//x = 0;
				//for(x=0;x<res;x++)
				//printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
				//printf("\n");
				return 0;
			}
			else
			{
				if(conn->itt_queue[hdr->itt] == NULL){
					printf("%d is NULL\n", hdr->itt);
					//printf("kiscsi_tcp_data_recv: [3]tcp_data_recv = 0x ");
					//x = 0;
					//for(x=0;x<res;x++)
					//printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
					//printf("\n\n");
					return 0;
				}
				if(conn->itt_queue[hdr->itt] != NULL)
				{
					work = conn->itt_queue[hdr->itt];
					sc = work->sc;



					//cvm_common_free_fpa_buffer((void *)work, CVMX_FPA_WQE_POOL, 0);
					//conn->itt_queue[hdr->itt] = NULL;





					//printf("itt_queue[%d] is NULL\n", hdr->itt);
				}
			}
		}

		//printf("before enter kiscsi_hdr_recv!\n");
		/*
		 * Verify and process incoming PDU header.
		 */
		rc = kiscsi_hdr_recv(conn, sc);  // ≥…π¶∑µªÿ0
		//printf("kiscsi_tcp_data_recv: [hdr_recv]  rc = %d, conn->in.len = %d, conn->in.datalen = %d, conn->in.offset = %d \n", rc, conn->in.len, conn->in.datalen, conn->in.offset);

		
		if (!rc && conn->in.datalen)
		{
			conn->in_progress = IN_PROGRESS_DATA_RECV;
			//printf("kiscsi_tcp_data_recv: hdr_recv succeed !\n");
		} 
		else if (rc) 
		{
			printf("kiscsi_tcp_data_recv: [1]iSCSI: bad hdr rc (%d) \n", rc);
			//iscsi_control_cnx_error(conn->handle, rc);
			return 0;
		}

	}

DATA:
	if (conn->in_progress == IN_PROGRESS_DATA_RECV && conn->in.copy) 
	{

		//debug_tcp("data_recv offset %d copy %d\n",  conn->in.offset, conn->in.copy);
		//printf("kiscsi_tcp_data_recv: data_recv offset %d copy %d\n",  conn->in.offset, conn->in.copy);
		//printf("kiscsi_tcp_data_recv: [before kiscsi_data_recv]  (conn->in.len -48) = %d,     conn->in.datalen = conn->in.hdr->dlength  = %d    \n", (conn->in.len -48), conn->in.datalen);
		
		rc =kiscsi_data_recv(conn);
		//printf("kiscsi_tcp_data_recv: [kiscsi_data_recv] rc = %d\n", rc );
		
		if (rc) 
		{
			if (rc == -EAGAIN) 
			{
				//rd_desc->count = conn->in.datalen -conn->in.ctask->sent;
				//goto again;
				printf("rc == -EAGAIN\n");
				return conn->in.offset;
			}
			printf("kiscsi_tcp_data_recv: [2]iSCSI: bad data rc (%d)\n", rc);
			//iscsi_control_cnx_error(conn->handle, rc);
			return 0;
		}

		// printf("kiscsi_tcp_recv: kiscsi_data_recv done ! rc = %d\n", rc);

		//printf("kiscsi_tcp_data_recv: [kiscsi_data_recv] rc = %d, conn->in.padding = %d\n", rc, conn->in.padding);
		conn->in.copy -= conn->in.padding;
		conn->in.offset += conn->in.padding;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
		//printf("\nkiscsi_tcp_recv: done successfully! \n");
		
	}
	 //Renjs
       if(conn->in.hdr->opcode == 0x31)
       	printf("kiscsi_tcp_data_recv:        opcode = 31!!!!!!!!!!!!!!!");

	// 0x21
	if(conn->in.hdr->opcode == ISCSI_OP_SCSI_CMD_RSP)
	{
		// 0x82
		if( conn->in.hdr->flags == 0x82 )
		{
			printf("kiscsi_tcp_data_recv: [0x82] continue to receive Response (, go to AA ) !!!\n");
			//continu = 1;
			//goto AA;
		}
		// add by Renjs
		if( conn->in.hdr->flags == 0x80 )
		{
			if( (conn->in.total_len - 48) < conn->in.datalen)
			{
				int recv_len = 0;


                                if(sc->app_work == 0)
                                {
                                        memset(conn->in.iscsi_skb, 0, 8192);
                                        do
                                        {
                                                res = cvm_so_recv(socket, conn->in.iscsi_skb + recv_len, conn->in.datalen - recv_len, 0);
                                                if(res >= 0)
                                                        recv_len += res;
                                                printf("res is %d,      conn->in.datalen is %d\n", res, conn->in.datalen);
                                        }while(recv_len < conn->in.datalen);
                                }
				
				res = recv_len;
                                conn->in.copy = res;
                                conn->in.offset = 0;
                                conn->in.len = res;
                                conn->in.total_len += res;

                                //if (conn->in.total_len - 48 == conn->in.datalen)
                                        conn->recv_data_again = 1;

                                conn->in_progress = IN_PROGRESS_DATA_RECV;
                                //printf ("kiscsi_tcp_data_recv[3]: continue recv in %d bytes, offset = %d, total = %d \n", res, conn->in.offset, conn->in.total_len);
                                //printf("kiscsi_tcp_data_recv: [3]tcp_data_recv = 0x ");
                                //x = 0;
                                //for(x=0;x<res;x++)
                                //printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
                                //printf("\n");
                                goto DATA;
			}
		}
		
	}
	//printf("after  f(sc->app_work == 0)   conn->in.hdr->opcode  is %x\n",conn->in.hdr->opcode);
	// 0x25
	if(conn->in.hdr->opcode == ISCSI_OP_SCSI_DATA_IN)
	{
		if(conn->in.hdr->flags == 0x81 || conn->in.hdr->flags == 0x80 || conn->in.hdr->flags == 0x00 || conn->in.hdr->flags == 0x83)
		{
			// 0x81, data recevied not enough. 
			if( (conn->in.total_len - 48) < conn->in.datalen)
			{
				//printf("kiscsi_tcp_data_recv: Not enough !!! \n");
				int recv_len = 0;
				

				if(sc->app_work == 0)
				{
					memset(conn->in.iscsi_skb, 0, 8192);
					do
					{
						res = cvm_so_recv(socket, conn->in.iscsi_skb + recv_len, conn->in.datalen - recv_len, 0);
						if(res >= 0)
							recv_len += res;
						printf("res is %d,	conn->in.datalen is %d\n", res, conn->in.datalen);
					}while(recv_len < conn->in.datalen);
				}
				else
				{
					int buffer_len = 0;
					data_list_t * data_head = (data_list_t *) sc->request_buffer_ptr;
          int i = 0;
					do
					{
            i++;
						buffer_len = data_head->data_len - data_head->copied;
						if(buffer_len > conn->in.datalen - recv_len)
							buffer_len = conn->in.datalen - recv_len;
						char * buf_ptr = ((char*)cvmx_phys_to_ptr(data_head->data_ptr)) + data_head->offset + data_head->copied;
						res = cvm_so_recv(socket, buf_ptr, buffer_len, 0);
						if(res >= 0)
						{
							recv_len += res;
							data_head->copied += res;
							if(data_head->copied == data_head->data_len)
							{
								data_head = data_head->next;
								sc->request_buffer_ptr = data_head;
							}
						}
            if(i%100 == 0)
            {
               // printf("!!!!!!!!!!!!! if(i == 0)   \n");
                //cvmx_pow_tag_sw_null();
                //cvmx_wait(1000);
                }
              
					}while(recv_len < conn->in.datalen);
				}
				res = recv_len;
				conn->in.copy = res;
				conn->in.offset = 0;
				conn->in.len = res;
				conn->in.total_len += res;

				//if (conn->in.total_len - 48 == conn->in.datalen)
					conn->recv_data_again = 1;
			
				conn->in_progress = IN_PROGRESS_DATA_RECV;
				//printf ("kiscsi_tcp_data_recv[2]: continue recv in %d bytes, offset = %d, total = %d \n", res, conn->in.offset, conn->in.total_len);		
				//printf("kiscsi_tcp_data_recv: [2]tcp_data_recv = 0x ");			
				//x = 0;
				//for(x=0;x<res;x++)
				//printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
				//printf("\n");
        //printf("   before goto DATA  \n");
				goto DATA;		
			}

		}

		/*if(conn->in.hdr->flags == 0x80)
		{
			// 0x2180 recevied but not processed
			if(conn->in.offset  < conn->in.len)
			{
				printf ("kiscsi_tcp_data_recv[3]: [0x2180 recevied but not processed] conn->in.len = %d, conn->in.offset = %d, total = %d \n", conn->in.len, conn->in.offset, conn->in.total_len);
				printf("kiscsi_tcp_data_recv: continue to process %d bytes, go to more !!! \n", (conn->in.len - conn->in.offset));
				continu = 1;
				goto more;
			}
			// 0x2180 not received
			else if(continu == 0)
			{
				printf ("kiscsi_tcp_data_recv[3]: [0x2180 not received] conn->in.len = %d, conn->in.offset = %d, total = %d \n", conn->in.len, conn->in.offset, conn->in.total_len);
				printf("kiscsi_tcp_data_recv: [0x80] continue to receive Response, go to AA !!! \n");
				continu = 1;
				goto AA;
			}
		}*/
	}
	
	//debug_tcp("f, processed %d from out of %d padding %d\n",
	//       conn->in.offset - offset, len, conn->in.padding);
	//BUG_ON(conn->in.offset - offset > len);

	//if (conn->in.offset - offset != len) {
	//	debug_tcp("continue to process %d bytes\n",
	//	       len - (conn->in.offset - offset));		
	//	goto more;
	//}

	//printf ("kiscsi_tcp_data_recv[3]: in %d bytes, offset = %d \n", conn->in.len, conn->in.offset);

	//printf("kiscsi_tcp_recv: done successfully! \n\n");
	conn->in.total_len = 0;
nomore:
	//printf("return nomore, %d\n", conn->in.offset);
	//BUG_ON(conn->in.offset - offset == 0);
	if(sc->app_work != NULL)
	{

		if(conn->in_progress != IN_PROGRESS_WAIT_HEADER)
		{
			printf("sc is ");
			for(x=0;x<16;x++)
			printf("%X ", (unsigned char *)sc->cmnd[x]);
			printf("\n");
			printf("kiscsi_tcp_data_recv: [1]tcp_data_recv = 0x ");
			x = 0;
			for(x=0;x<res;x++)
			printf("%x ", (unsigned char *)conn->in.iscsi_skb[x]);
			printf("\n");
		}


		if(conn->in.hdr->flags == 0x81)
		{	
			if(conn->itt_queue[conn->in.hdr->itt] != NULL)
			{
				cvm_common_free_fpa_buffer((void *)conn->itt_queue[conn->in.hdr->itt], CVMX_FPA_WQE_POOL, 0);
				conn->itt_queue[conn->in.hdr->itt] = NULL;
			}

			iSCSI_context * current_context = (iSCSI_context *) sc->context;
			if(current_context->itt_used == 0)
				printf("current_context itt_used is 0\n");
			current_context->itt_used--;
      ittdec++;

			cvmx_wqe_t * work = (cvmx_wqe_t *)sc->app_work;
			iSCSI_Params * params_ptr = (iSCSI_Params *) work->packet_data;

			//Renjs  print reading
			/*
			printf("print reading!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
			char* ss = (char *)cvmx_phys_to_ptr(params_ptr->data_head->data_ptr);
			int num;
			for(num = 0; num < 100; num++)
				printf("%x " ,ss[num]);
			printf("\n");
			*/
			/*
			work->grp = params_ptr->cmd.group;
			cvmx_pow_work_submit(work, work->tag, work->tag_type, work->qos, work->grp);
			*/

			
			data_list_t * data_head = (data_list_t *)params_ptr->data_head;
			while(data_head != NULL)
			{
				data_list_t * temp_data_head = data_head;
				data_head = data_head->next; 
				cvm_common_free_fpa_buffer((void*)cvmx_phys_to_ptr(temp_data_head->data_ptr), CVMX_FPA_PACKET_POOL, 0);
				cvm_common_free_fpa_buffer((void*)temp_data_head, CVMX_FPA_WQE_POOL, 0);
			}
			cvm_common_free_fpa_buffer((void*)work, CVMX_FPA_WQE_POOL, 0);
			

			cvm_common_free_fpa_buffer((void*)sc, CVMX_FPA_PACKET_POOL, 0);
		}
		/*if(((struct iscsi_conn *)(conn->handle))->ctask != NULL)
		{
			cvm_common_free_fpa_buffer((void*)(((struct iscsi_conn *)(conn->handle))->ctask), CVMX_FPA_PACKET_POOL, 0);
			((struct iscsi_conn *)(conn->handle))->ctask = NULL;
		}*/
	}
	return conn->in.offset ;

again:
	printf("return again, %d\n", conn->in.offset);
	//debug_tcp("c, processed %d from out of %d rd_desc_cnt %d\n", conn->in.offset - offset, len, rd_desc->count);
	//BUG_ON(conn->in.offset - offset == 0);
	//BUG_ON(conn->in.offset - offset > len);

	return conn->in.offset;
}








/*
//static void iscsi_tcp_data_ready(struct sock *sk, int flag)
static void kiscsi_tcp_data_ready(struct iscsi_conn *conn)
{
	struct iscsi_conn *conn = (struct iscsi_conn*)sk->sk_user_data;
	read_descriptor_t rd_desc;

	//read_lock(&sk->sk_callback_lock);

	// use rd_desc to pass 'conn' to iscsi_tcp_data_recv 
	
	iscsi_conn_set(&rd_desc, conn);
	rd_desc.count = 0;
 
	tcp_read_sock(sk, &rd_desc, iscsi_tcp_data_recv);

	read_unlock(&sk->sk_callback_lock);
}
*/






/*
static void
iscsi_tcp_state_change(struct sock *sk)
{
	struct iscsi_conn *conn = (struct iscsi_conn*)sk->sk_user_data;
	struct iscsi_session *session = conn->session;

	if (sk->sk_state == TCP_CLOSE_WAIT ||
	    sk->sk_state == TCP_CLOSE) {
		debug_tcp("iscsi_tcp_state_change: TCP_CLOSE\n");
		conn->c_stage = ISCSI_CNX_CLEANUP_WAIT;

		
		spin_lock_bh(&session->conn_lock);
		if (session->conn_cnt == 1 ||
		    session->leadconn == conn) {
			session->state = ISCSI_STATE_FAILED;
		}
		spin_unlock_bh(&session->conn_lock);


		
		iscsi_control_cnx_error(conn->handle, ISCSI_ERR_CNX_FAILED);
	}
	conn->old_state_change(sk);
}
*/

#ifdef CMD
/*
 * Called when more output buffer space is available for this socket.
 */
static void
iscsi_write_space(struct sock *sk)
{
	struct iscsi_conn *conn = (struct iscsi_conn*)sk->sk_user_data;
	conn->old_write_space(sk);
	debug_tcp("iscsi_write_space: cid %d\n", conn->id);
	conn->suspend = 0; wmb();
	schedule_work(&conn->xmitwork);
}

static void
iscsi_conn_set_callbacks(struct iscsi_conn *conn)
{
	struct sock *sk = conn->sock->sk;

	/* assign new callbacks */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = conn;
	conn->old_data_ready = sk->sk_data_ready;
	conn->old_state_change = sk->sk_state_change;
	conn->old_write_space = sk->sk_write_space;
	//
	//
	sk->sk_data_ready = iscsi_tcp_data_ready;
	//
	//
	//
	sk->sk_state_change = iscsi_tcp_state_change;
	sk->sk_write_space = iscsi_write_space;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void
iscsi_conn_restore_callbacks(struct iscsi_conn *conn)
{
	struct sock *sk = conn->sock->sk;

	/* restore socket callbacks, see also: iscsi_conn_set_callbacks() */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data    = NULL;
	sk->sk_data_ready   = conn->old_data_ready;
	sk->sk_state_change = conn->old_state_change;
	sk->sk_write_space  = conn->old_write_space;
	sk->sk_no_check	 = 0;
	write_unlock_bh(&sk->sk_callback_lock);
}
#endif







/*
 * iscsi_sendhdr - send PDU Header via tcp_sendpage()
 * (Tx, Fast Path)
 */
//static inline int kiscsi_sendhdr(struct iscsi_conn *conn, struct iscsi_buf *buf)
//static inline int kiscsi_sendhdr(struct iscsi_conn *conn, struct iscsi_mgmt_task * mtask)
static inline int kiscsi_sendhdr(struct iscsi_conn *conn, struct iscsi_buf *buf)
{
	int socket = conn->socket;
	int flags = 0; /* MSG_DONTWAIT; */
	int res, offset, size;
	offset = buf->offset + buf->sent;
	size = buf->length - buf->sent;

	// ¥Ú”°
	//printf("kiscsi_sendhdr: sendhdr = 0x ");
	//int x = 0;
	//for(x=0; x<size; x++)
	//	printf("%x ", ((unsigned char *)buf->buffer)[x]);
	//printf("\n");
	//printf("kiscsi_sendhdr: ctask->headbuf.length = buf->length = %d \n", buf->length);
	//printf("kiscsi_sendhdr: ctask->headbuf.offset = buf->offset = %d \n", buf->offset);
	//printf("kiscsi_sendhdr: ctask->headbuf.sent = buf->sent = %d \n\n", buf->sent);
	//printf("kiscsi_sendhdr: offset = buf->offset + buf->sent  = %d \n\n", offset);
	//printf("kiscsi_sendhdr: size = buf->length - buf->sent   = %d \n\n", size);

	res = cvm_so_send (socket, buf->buffer, size, 0);

	if (res >= 0) 
	{
		buf->sent += res;
		if (size != res)
			return -EAGAIN;
		return 0;
	} 
	else if (res == -EAGAIN) 
	{
		conn->suspend = 1;
	} 
	else if (res == -EPIPE) {
		conn->suspend = 1;
	}

	return res;
}









/*
 * iscsi_sendpage - send one page of iSCSI Data-Out.
 * (Tx, Fast Path)
 */
static inline int kiscsi_sendpage(struct iscsi_conn *conn, struct iscsi_buf *buf, int *count, int *sent)
{

	int socket = conn->socket;
	int flags = 0; 
	int res, offset, size;

	// size = buf->sg.length - buf->sent;
	//size = mtask->sendbuf_length - mtask->sendbuf_sent;
	//printf("kiscsi_sendpage: buf = &ctask->sendbuf, buf->length=%d, buf->sent=%d, size = buf->length - buf->sent =%d\n",  buf->length, buf->sent, (buf->length - buf->sent));
	//printf("sendpage:      buf->length = %d  buf->sent = %d \n ",buf->length,buf->sent);
	size = buf->length - buf->sent;//size means how much to sent this time
	
	if (size > *count)
	{
		size = *count;
		printf("kiscsi_sendpage: size == imm_count\n");
	}
	offset = buf->offset + buf->sent;
	

	// ¥Ú”°
	//printf("sendpage= 0x ");
	//int x = 0;
	//for(x=0;x<size;x++)
	//	printf("%x ", ((unsigned char *)buf->buffer)[x]);
	//printf("\n");

  if(conn->ctask == NULL || conn->ctask->sc->app_work == 0)
  {
          res = cvm_so_send (socket, buf->buffer, size, 0);
  }
  else
  {
          int data_to_send = size;
          uint64_t n = 0;
          uint64_t nn =0;
          data_list_t * data_head = (data_list_t *) buf->buffer;
          while(1)
          {
                  res = cvm_so_send (socket, (char*)cvmx_phys_to_ptr(data_head->data_ptr) + data_head->offset + data_head->copied, data_head->data_len - data_head->copied, 0);
                  if(res < 0)
                  {
                          n++;
                          if(n % 100 == 0)
                          {
                                  cvmx_pow_tag_sw_null();
                          }

                          continue;

                  }
                  data_head->copied += res;
                  
                  data_to_send -= res;

                  if(data_head->copied == data_head->data_len)
                  {
                          data_head = data_head->next;
                  }

                  if(data_to_send == 0)
                          break;
                  else if(data_to_send < 0 || data_head == NULL)
                  {                        
                          break;
                  }
          }

          res = size;
  }

	if (res >= 0)
	{
		buf->sent += res;
		*count -= res;
		*sent += res;
		if (size != res)
			return -EAGAIN;
		return 0;
	} 
	else if (res == -EAGAIN) 
	{
		conn->suspend = 1;
	} 
	else if (res == -EPIPE)
	{
		conn->suspend = 1;
	}
	
	return res;
}








/*
 * iscsi_solicit_data_cont - initialize next Data-Out
 *
 * Initialize next Data-Out within this R2T sequence and continue
 * to process next Scatter-Gather element(if any) of this SCSI command.
 *
 * Called under connection lock.
 */
static void
iscsi_solicit_data_cont(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask,
			struct iscsi_r2t_info *r2t, int left)
{
	struct iscsi_data *hdr;
	struct iscsi_data_task *dtask;
	struct scsi_cmnd *sc = ctask->sc;
	int new_offset;

	// dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	dtask = malloc(sizeof(struct iscsi_data_task));
	
	hdr = &dtask->hdr;
	hdr->flags = 0;
	hdr->rsvd2[0] = hdr->rsvd2[1] = hdr->rsvd3 =
		hdr->rsvd4 = hdr->rsvd5 = hdr->rsvd6 = 0;
	hdr->ttt = r2t->ttt;
	//hdr->datasn = htonl(r2t->solicit_datasn);
	hdr->datasn = r2t->solicit_datasn;
	r2t->solicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	memset(hdr->lun, 0, 8);
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = r2t->exp_statsn;
	new_offset = r2t->data_offset + r2t->sent;
	//hdr->offset = htonl(new_offset);
	hdr->offset = new_offset;
	if (left > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		r2t->data_count = conn->max_xmit_dlength;
	} else {
		hton24(hdr->dlength, left);
		r2t->data_count = left;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}
	
	//iscsi_buf_init_hdr(conn, &r2t->headbuf, (char*)hdr, (u8 *)dtask->hdrext);
	r2t->headbuf.buffer =  (char*)hdr;
	r2t->headbuf.length = sizeof(struct iscsi_data);

	if (sc->use_sg) {
		//BUG_ON(ctask->bad_sg == r2t->sg);
		if (!iscsi_buf_left(&r2t->sendbuf)) {
			//iscsi_buf_init_sg(&r2t->sendbuf, r2t->sg);
			//r2t->sg += 1;
		}
	} else {
		// iscsi_buf_init_virt(&ctask->sendbuf,  (char*)sc->request_buffer + new_offset, r2t->data_count);
		ctask->sendbuf.buffer = (char*)sc->request_buffer + new_offset;
		ctask->sendbuf.length =  r2t->data_count;
		ctask->sendbuf.offset = 0;
		ctask->sendbuf.sent = 0;
	}
	//list_add(&dtask->item, &ctask->dataqueue);
}







static void
iscsi_unsolicit_data_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_data *hdr;
	struct iscsi_data_task *dtask;

	//dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	dtask = malloc(sizeof(struct iscsi_data_task));
	
	hdr = &dtask->hdr;
	hdr->rsvd2[0] = hdr->rsvd2[1] = hdr->rsvd3 = hdr->rsvd4 = hdr->rsvd5 = hdr->rsvd6 = 0;	
	hdr->ttt = ISCSI_RESERVED_TAG;
	//hdr->datasn = htonl(ctask->unsol_datasn);
	hdr->datasn = ctask->unsol_datasn;
	ctask->unsol_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	memset(hdr->lun, 0, 8);
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	//hdr->exp_statsn = htonl(conn->exp_statsn);
	//hdr->offset = htonl(ctask->total_length - ctask->r2t_data_count - ctask->unsol_count);
	hdr->exp_statsn = conn->exp_statsn;
	hdr->offset = ctask->total_length - ctask->r2t_data_count - ctask->unsol_count;

	if (ctask->unsol_count > conn->max_xmit_dlength) 
	{
		hton24(hdr->dlength, conn->max_xmit_dlength);
		ctask->data_count = conn->max_xmit_dlength;
		hdr->flags = 0;
	} 
	else 
	{
		hton24(hdr->dlength, ctask->unsol_count);
		ctask->data_count = ctask->unsol_count;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}

	//iscsi_buf_init_hdr(conn, &ctask->headbuf, (char*)hdr, (unsigned char *)dtask->hdrext);
	ctask->headbuf.buffer =  (char*)hdr;
	ctask->headbuf.length = sizeof(struct iscsi_data);
		
	//list_add(&dtask->item, &ctask->dataqueue);
}





/*
 * Initialize iSCSI SCSI_READ or SCSI_WRITE commands
 */
static void
iscsi_cmd_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask,
		struct scsi_cmnd *sc)
{
	//printf("iscsi_cmd_init:  sc->sc_data_direction =  %d \n", sc->sc_data_direction);
	struct iscsi_session *session = conn->session;

	ctask->sc = sc;
	ctask->conn = conn;

	memset(&ctask->hdr, 0, sizeof(struct iscsi_cmd));
	
	ctask->hdr.opcode = ISCSI_OP_SCSI_CMD;
	ctask->hdr.flags = ISCSI_ATTR_SIMPLE;

	// fixed 
	ctask->hdr.rsvd2 = 0;
	ctask->hdr.cmdrn = 0;
	ctask->hdr.hlength = 0;

	// all 0
	ctask->hdr.lun[1] = sc->device->lun;
	//printf("\nctask->hdr.lun[1] = sc->device->lun = %d\n", ctask->hdr.lun[1]);

	//printf("ctask->hdr.lun[] = ");
	//int y=0; 
	//for(y=0; y<8; y++)
	//{
	//	printf("%x ", ctask->hdr.lun[y]);
	//}
	//printf("\n");
	
	//ctask->hdr.itt = htonl(ctask->itt);
	//ctask->hdr.data_length = htonl(sc->request_bufflen);
	//ctask->hdr.cmdsn = htonl(session->cmdsn); session->cmdsn++;
	//ctask->hdr.exp_statsn = htonl(conn->exp_statsn);
	ctask->hdr.itt = (ctask->itt);
	
	//printf("iscsi_cmd_init: ctask->hdr.itt = (ctask->itt) = %d \n", ctask->itt);


	//printf("iscsi_cmd_init: sc->request_bufflen = %d \n", sc->request_bufflen);
	ctask->hdr.data_length = (sc->request_bufflen);
	//printf("iscsi_cmd_init: ctask->hdr.data_length = %d \n", ctask->hdr.data_length);

	ctask->hdr.cmdsn = (session->cmdsn); 
	session->cmdsn++;
	//if(session->cmdsn == 23660)
	//	session->cmdsn = 1;
	
	ctask->hdr.exp_statsn = (conn->exp_statsn);
	//printf("iscsi_cmd_init: ctask->hdr.exp_statsn = (conn->exp_statsn) = %d!!!!!!!!!!!!!!!!!!!!!!!!!!\n", conn->exp_statsn);

	//int i;
	//printf("iscsi_cmd_init: sc->cmnd = ");
	//for(i=0; i<16; i++)
	//{
	//	printf("%x ", sc->cmnd[i]);
	//}
	//printf("\niscsi_cmd_init: sc->cmd_len = %d", sc->cmd_len);
	//printf("\n");
	
	
	memcpy(ctask->hdr.cdb, sc->cmnd, sc->cmd_len);
	//printf("ctask->hdr.cdb is %s\n", ctask->hdr.cdb ? "not NULL" : "NULL");
	memset(&ctask->hdr.cdb[sc->cmd_len], 0, 16 - sc->cmd_len);


	//printf("iscsi_cmd_init: ctask->hdr.cdb = ");
	//for(i=0; i<16; i++)
	//{
	//	printf("%x ", ctask->hdr.cdb[i]);
	//}
	//printf("\n");
	
	ctask->in_progress = IN_PROGRESS_IDLE;
	ctask->sent = 0;
	ctask->sg_count = 0;

	ctask->total_length = sc->request_bufflen;

	if (sc->sc_data_direction == DMA_TO_DEVICE) {
		ctask->exp_r2tsn = 0;
		ctask->hdr.flags |= ISCSI_FLAG_CMD_WRITE;
		ctask->in_progress = IN_PROGRESS_WRITE;
		conn->ctask_in_progress = IN_PROGRESS_WRITE;
		
		//BUG_ON(ctask->total_length == 0);
		if (sc->use_sg) {
			//struct scatterlist *sg = sc->request_buffer;

			//iscsi_buf_init_sg(&ctask->sendbuf, &sg[0]);
			//ctask->sg = sg + 1;
			//ctask->bad_sg = sg + sc->use_sg;
			printf("ctask from SCSI using sg !!\n");
		} 
		else {
			ctask->sendbuf.buffer = sc->request_buffer;
			ctask->sendbuf.length = sc->request_bufflen;
			ctask->sendbuf.offset = 0;
			ctask->sendbuf.sent = 0;
			//ctask->sendbuf.buffer = (void*)sc->cmnd;
			//ctask->sendbuf.length = (int)sc->cmd_len;			
			//iscsi_buf_init_virt(&ctask->sendbuf, sc->request_buffer, sc->request_bufflen);
			//BUG_ON(sc->request_bufflen > PAGE_SIZE);
		}

		/*
		 * Write counters:
		 *
		 *	imm_count	bytes to be sent right after
		 *			SCSI PDU Header
		 *
		 *	unsol_count	bytes(as Data-Out) to be sent
		 *			without	R2T ack right after
		 *			immediate data
		 *
		 *	r2t_data_count	bytes to be sent via R2T ack's
		 */
		ctask->imm_count = 0;
		ctask->unsol_count = 0;
		ctask->unsol_datasn = 0;
		ctask->xmstate = XMSTATE_W_HDR;
		
		if (session->imm_data_en) 
		{
			if (ctask->total_length >= session->first_burst) {
				ctask->imm_count = min(session->first_burst,
							conn->max_xmit_dlength);
			} else {
				ctask->imm_count = min(ctask->total_length,
							conn->max_xmit_dlength);
			}
			hton24(ctask->hdr.dlength, ctask->imm_count);
			ctask->xmstate |= XMSTATE_IMM_DATA;
		} 
		else {
			zero_data(ctask->hdr.dlength);
		}
		
		if (!session->initial_r2t_en) {
			ctask->unsol_count=min(session->first_burst,
				ctask->total_length) - ctask->imm_count;
		}

		if (!ctask->unsol_count) {
			/* No unsolicit Data-Out's */
			ctask->hdr.flags |= ISCSI_FLAG_CMD_FINAL;
		} 
		else {
			ctask->xmstate |= XMSTATE_UNS_HDR | XMSTATE_UNS_INIT;
		}

		ctask->r2t_data_count = ctask->total_length - ctask->imm_count -ctask->unsol_count;

		//printf("iscsi_cmd_init: cmd [ctask->itt = %d, ctask->total_length = %d, ctask->imm_count = %d, ctask->unsol_count = %d, ctask->r2t_data_count = %d]\n",
		//	   ctask->itt, ctask->total_length, ctask->imm_count,
		//	   ctask->unsol_count, ctask->r2t_data_count);
	} 

	else {	
		ctask->hdr.flags |= ISCSI_FLAG_CMD_FINAL;
		if (sc->sc_data_direction == DMA_FROM_DEVICE)
		{
			ctask->hdr.flags |= ISCSI_FLAG_CMD_READ;
			//printf("iscsi_cmd_init: ctask->hdr.flags |= ISCSI_FLAG_CMD_READ, ctask->hdr.flags= %x \n", ctask->hdr.flags);
		}	
		ctask->datasn = 0;
		ctask->in_progress = IN_PROGRESS_READ;
		conn->ctask_in_progress = IN_PROGRESS_READ;
		ctask->xmstate = XMSTATE_R_HDR;
		zero_data(ctask->hdr.dlength);
	}
	//ctask->headbuf = &ctask->hdr;
	//ctask->headbuf_length = sizeof(struct iscsi_cmd);
	ctask->headbuf.buffer = &ctask->hdr;
	ctask->headbuf.length = sizeof(struct iscsi_cmd);
	ctask->headbuf.offset = 0;
	ctask->headbuf.sent = 0;
	
	//printf("iscsi_cmd_init: ctask->headbuf.buffer = 0x ");
	//int x = 0;
	//for(x=0; x<ctask->headbuf.length; x++)
	//	printf("%x ", ((unsigned char *)ctask->headbuf.buffer)[x]);
	//printf("\n");
	//printf("iscsi_cmd_init: ctask->headbuf.length = %d \n", ctask->headbuf.length);
	//printf("iscsi_cmd_init: ctask->headbuf.offset = %d \n", ctask->headbuf.offset);
	//printf("iscsi_cmd_init: ctask->headbuf.sent = %d \n\n", ctask->headbuf.sent);
	
	conn->ctask = ctask;
	//iscsi_buf_init_hdr(conn, &ctask->headbuf, (char*)&ctask->hdr,  (u8 *)ctask->hdrext);
}









/*
 * iscsi_mtask_xmit - xmit management(immediate) task
 *
 * The function can return -EAGAIN in which case caller must
 * call it again later, or recover. '0' return code means successful
 * xmit.
 *
 * Management xmit state machine consists of two states:
 *	IN_PROGRESS_IMM_HEAD - PDU Header xmit in progress
 *	IN_PROGRESS_IMM_DATA - PDU Data xmit in progress
 */
static int
kiscsi_mtask_xmit(struct iscsi_conn *conn, struct iscsi_mgmt_task *mtask)
{

	//debug_scsi("mtask deq [cid %d state %x itt 0x%x]\n",
	//	conn->id, mtask->xmstate, mtask->itt);

	printf("kiscsi_mtask_xmit: mtask deq [cid %d state %x itt 0x%x]\n", conn->id, mtask->xmstate, mtask->itt);

	if (mtask->xmstate & XMSTATE_IMM_HDR) 
	{
		mtask->xmstate &= ~XMSTATE_IMM_HDR; 
		// «Â¡„

		if (mtask->data_count)
			mtask->xmstate |= XMSTATE_IMM_DATA;

		//if (kiscsi_sendhdr(conn, &mtask->headbuf)) 
		//if (kiscsi_sendhdr(conn, &mtask)) 
		if (kiscsi_sendhdr(conn, &mtask->headbuf)) 
		{
			// ∑¢ÀÕ ß∞‹
			mtask->xmstate |= XMSTATE_IMM_HDR;
			if (mtask->data_count)
				mtask->xmstate &= ~XMSTATE_IMM_DATA;
			// ÷ÿ–¬ªÿµΩXMSTATE_IMM_DATA
			return -EAGAIN;
		}
	}

	if (mtask->xmstate & XMSTATE_IMM_DATA) 
	{
		//BUG_ON(!mtask->data_count);
		mtask->xmstate &= ~XMSTATE_IMM_DATA;
		/* FIXME: implement.
		 * Virtual buffer could be spreaded accross multiple pages...
		 */
		do 
		{
			if (kiscsi_sendpage(conn, &mtask->sendbuf, &mtask->data_count, &mtask->sent)) 
			{
				// ∑¢ÀÕ ß∞‹
				mtask->xmstate |= XMSTATE_IMM_DATA;
				return -EAGAIN;
			}
		} while (mtask->data_count);
	}


	//kiscsi_tcp_data_recv(conn);
	//BUG_ON(mtask->xmstate != XMSTATE_IDLE);
	return 0;
}














/*
 * iscsi_data_xmit - xmit any command into the scheduled connection
 *
 * The function can return -EAGAIN in which case the caller must
 * re-schedule it again later or recover. '0' return code means successful
 * xmit.
 *
 * Common data xmit state machine consists of two states:
 *	IN_PROGRESS_XMIT_IMM - xmit of Immediate PDU in progress
 *	IN_PROGRESS_XMIT_SCSI - xmit of SCSI command PDU in progress
 */
static int kiscsi_data_xmit(struct iscsi_conn *conn)
{
	if(conn->in_progress_xmit != IN_PROGRESS_XMIT_SCSI)
		printf("kiscsi_data_xmit: conn->in_progress_xmit != IN_PROGRESS_XMIT_SCSI!!!!!!!!!!\n");
	if(!(conn->ctask))
		printf("kiscsi_data_xmit: conn->ctask = NULL\n");

	while (conn->in_progress_xmit == IN_PROGRESS_XMIT_SCSI && (conn->ctask )) 
	{
		if (kiscsi_ctask_xmit(conn, conn->ctask))
		{
			conn->session->cmdsn--;
			return -EAGAIN;
		}
		
		conn->ctask = NULL;
		
	}

	while (conn->mtask )
	{
		struct iscsi_session *session = conn->session;

		conn->in_progress_xmit = IN_PROGRESS_XMIT_IMM;

		if (kiscsi_mtask_xmit(conn, conn->mtask))
			return -EAGAIN;

		if (conn->mtask->hdr.itt == ISCSI_RESERVED_TAG) 
		{

		}

		conn->mtask = NULL;

	}


	conn->in_progress_xmit = IN_PROGRESS_XMIT_SCSI;
	
	
	return 0;
}


//
//
//
//
//
//
//
//
//


//static void kiscsi_xmitworker(void *data)
void kiscsi_xmitworker(void *data)
{
	struct iscsi_conn *conn = data;
	if (conn->suspend)
		goto out;
	if (kiscsi_data_xmit(conn)) 
	{
		if (conn->c_stage == ISCSI_CNX_CLEANUP_WAIT ||
		    conn->c_stage == ISCSI_CNX_STOPPED ||
		    conn->suspend)
			goto out;
	}
out:
	return;
}






#define FAILURE_BAD_HOST		1
#define FAILURE_SESSION_FAILED		2
#define FAILURE_SESSION_FREED		3
#define FAILURE_WINDOW_CLOSED		4
#define FAILURE_SESSION_TERMINATE	5

int ggitt =0;


int
iscsi_queuecommand(struct scsi_cmnd *sc, void (*done)(struct scsi_cmnd *))
{

	struct Scsi_Host *host;
	int reason = 0;
	struct iscsi_session *session;
	struct iscsi_conn *conn = NULL;
	struct iscsi_cmd_task *ctask = NULL;
	sc->scsi_done = done;
	sc->result = 0;
	host = sc->device->host;
	
	session = (struct iscsi_session*)host->hostdata;

	if (session->state != ISCSI_STATE_LOGGED_IN) 
	{
		if (session->state == ISCSI_STATE_FAILED) {
			reason = FAILURE_SESSION_FAILED;
			goto fault;
		} else if (session->state == ISCSI_STATE_TERMINATE) {
			reason = FAILURE_SESSION_TERMINATE;
			goto fault;
		}
		reason = FAILURE_SESSION_FREED;
		goto fault;
	}

	

	conn = session->leadconn;
	
	ctask = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	if(ctask == NULL)
		printf("Alloc ctask error!\n");


    int cnn_itt = (conn->cn_itt + 1) % ITTLENGTH;
	int k = 0;
    for(k =0;k<ITTLENGTH;k++)
	{
                if(conn->itt_queue[cnn_itt] == NULL)
                        break;
                cnn_itt=(cnn_itt+1) % ITTLENGTH;
    }
	if(k == ITTLENGTH)
	{
		printf("itt queue is full!	%d\n", ((iSCSI_context *) session->context)->itt_used);
	}
	struct itt_work * new_work = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
	new_work->sc = sc;
	sc->context = session->context;
	conn->itt_queue[cnn_itt] = new_work;
	conn->cn_itt = cnn_itt;
	ctask->itt = cnn_itt;

	
	iscsi_cmd_init(conn, ctask, sc);

	
	kiscsi_xmitworker((void *)conn);

	if(sc->sc_data_direction == DMA_TO_DEVICE)
	{	
		cvmx_wqe_t * work = (cvmx_wqe_t *)new_work->sc->app_work;
		iSCSI_Params * params_ptr = (iSCSI_Params *) work->packet_data;
		data_list_t * data_head = (data_list_t *)params_ptr->data_head;
		while(data_head != NULL)
		{
			data_list_t * temp_data_head = data_head;
			data_head = data_head->next; 
			cvm_common_free_fpa_buffer((void*)cvmx_phys_to_ptr(temp_data_head->data_ptr), CVMX_FPA_PACKET_POOL, 0);
			cvm_common_free_fpa_buffer((void*)temp_data_head, CVMX_FPA_WQE_POOL, 0);
		}
		cvm_common_free_fpa_buffer((void*)work, CVMX_FPA_WQE_POOL, 0);
		cvm_common_free_fpa_buffer((void*)sc, CVMX_FPA_PACKET_POOL, 0);
		

		goto workdone;
	}

	iSCSI_context * current_context = (iSCSI_context *) session->context;
	if(current_context->state == iSCSI_SEND_LOGIN_CMD)
	{
		cvmx_pow_tag_sw_null();
		current_context->syn_among_core = 1;
		while(current_context->syn_among_core != 0)
		{
			//cvmx_wait(8000000);
			//printf("-----------------------------current_context->syn_among_core is %d\n", current_context->syn_among_core);
		}
	}
	else
	{
		if(ctask == NULL)
			printf("[queuecommand]ctask is NULL\n");
		else
			cvm_common_free_fpa_buffer(ctask, CVMX_FPA_PACKET_POOL, 0);
        conn->ctask = NULL;
		current_context->itt_used++;
		return 0;
	}
	printf("Start recv data!!!!!!!!!!!!!!!!!!!!!!!!!!11\n");
	
		
	kiscsi_tcp_data_recv(conn, sc);
	
workdone:
	
	cvm_common_free_fpa_buffer(new_work, CVMX_FPA_WQE_POOL, 0);
    conn->itt_queue[cnn_itt] = NULL;

	cvm_common_free_fpa_buffer(ctask, CVMX_FPA_PACKET_POOL, 0);
	conn->ctask = NULL;

	return 0;

reject:

	return SCSI_MLQUEUE_HOST_BUSY;

fault:
	printf("iSCSI: cmd 0x%x is not queued (%d)\n", sc->cmnd[0], reason);
	sc->sense_buffer[0] = 0x70;
	sc->sense_buffer[2] = NOT_READY;
	sc->sense_buffer[7] = 0x6;
	sc->sense_buffer[12] = 0x08;
	sc->sense_buffer[13] = 0x00;
	sc->result = (DID_NO_CONNECT << 16);
	switch (sc->cmnd[0]) {
	case INQUIRY:
	case REQUEST_SENSE:
		sc->resid = sc->cmnd[4];
	case REPORT_LUNS:
		sc->resid = sc->cmnd[6] << 24;
		sc->resid |= sc->cmnd[7] << 16;
		sc->resid |= sc->cmnd[8] << 8;
		sc->resid |= sc->cmnd[9];
	default:
		sc->resid = sc->request_bufflen;
	}
	sc->scsi_done(sc);
	return 0;
}



#ifdef CMD

//  ÃÓ≥‰iscsi_queue
static int
iscsi_pool_init(struct iscsi_queue *q, int max, void ***items, int item_size)
{
	int i;

	*items = kmalloc(max * sizeof(void*), GFP_KERNEL);
	if (*items == NULL)
		return -ENOMEM;

	q->max = max;
	q->pool = kmalloc(max * sizeof(void*), GFP_KERNEL);
	if (q->pool == NULL) {
		kfree(*items);
		return -ENOMEM;
	}

	q->queue = kfifo_init((void*)q->pool, max * sizeof(void*),
			      GFP_KERNEL, NULL);
	if (q->queue == ERR_PTR(-ENOMEM)) {
		kfree(q->pool);
		kfree(*items);
		return -ENOMEM;
	}

	for (i = 0; i < max; i++) 
	{
		q->pool[i] = kmalloc(item_size, GFP_KERNEL);
		if (q->pool[i] == NULL) {
			int j;
			for (j = 0; j < i; j++) {
				kfree(q->pool[j]);
			}
			kfifo_free(q->queue);
			kfree(q->pool);
			kfree(*items);
			return -ENOMEM;
		}
		memset(q->pool[i], 0, item_size);
		(*items)[i] = q->pool[i];
		__kfifo_put(q->queue, (void*)&q->pool[i], sizeof(void*));
	}
	return 0;
}


static void
iscsi_pool_free(struct iscsi_queue *q, void **items)
{
	int i;

	for (i = 0; i < q->max; i++)
		kfree(items[i]);
	kfree(q->pool);
	kfree(items);
}


#endif






// static int kiscsi_ctask_xmit(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
int kiscsi_ctask_xmit(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_r2t_info *r2t = NULL;

// READ
	if (ctask->xmstate & XMSTATE_R_HDR) 
	{
		ctask->xmstate &= ~XMSTATE_R_HDR;
		
		if (!kiscsi_sendhdr(conn, &ctask->headbuf)) 
		{
			return 0; /* wait for Data-In */
		}
		ctask->xmstate |= XMSTATE_R_HDR;
		
		return -EAGAIN;
	}

// WRITE
	if (ctask->xmstate & XMSTATE_W_HDR) 
	{
		ctask->xmstate &= ~XMSTATE_W_HDR;
		if (kiscsi_sendhdr(conn, &ctask->headbuf)) 
		{
			ctask->xmstate |= XMSTATE_W_HDR;
			return -EAGAIN;
		}
	}


	if (ctask->xmstate & XMSTATE_IMM_DATA) 
	{
		ctask->xmstate &= ~XMSTATE_IMM_DATA;
		if (kiscsi_sendpage(conn, &ctask->sendbuf, &ctask->imm_count, &ctask->sent)) 
		{
			ctask->xmstate |= XMSTATE_IMM_DATA;
			return -EAGAIN;
		}
	}




	if (ctask->xmstate & XMSTATE_UNS_HDR) {
		ctask->xmstate &= ~XMSTATE_UNS_HDR;
_unsolicit_head_again:
		ctask->xmstate |= XMSTATE_UNS_DATA;
		if (ctask->xmstate & XMSTATE_UNS_INIT) {
			iscsi_unsolicit_data_init(conn, ctask);
			ctask->xmstate &= ~XMSTATE_UNS_INIT;
		}
		if (kiscsi_sendhdr(conn, &ctask->headbuf)) {
			ctask->xmstate &= ~XMSTATE_UNS_DATA;
			ctask->xmstate |= XMSTATE_UNS_HDR;
			return -EAGAIN;
		}
		// debug_scsi("uns dout [itt 0x%x dlen %d sent %d]\n", ctask->itt, ctask->unsol_count, ctask->sent);
		printf("uns dout [itt 0x%x dlen %d sent %d]\n", ctask->itt, ctask->unsol_count, ctask->sent);
	}




	if (ctask->xmstate & XMSTATE_UNS_DATA) {
		//BUG_ON(!ctask->data_count);
		ctask->xmstate &= ~XMSTATE_UNS_DATA;
		//while (1) {
			int start = ctask->sent;
			if (kiscsi_sendpage(conn, &ctask->sendbuf, &ctask->data_count, &ctask->sent)) 
			{
				ctask->unsol_count -= ctask->sent - start;
				ctask->xmstate |= XMSTATE_UNS_DATA;
				/* will continue with this ctask later.. */
				return -EAGAIN;
			}
			//BUG_ON(ctask->sent > ctask->total_length);
			ctask->unsol_count -= ctask->sent - start;
			printf("XMSTATE_UNS_DATA ... ctask->unsol_count = %d\n", ctask->unsol_count );
			//if (!ctask->data_count)
			//	break;
		//	iscsi_buf_init_sg(&ctask->sendbuf, &ctask->sg[ctask->sg_count++]);
		//}
		//BUG_ON(ctask->unsol_count < 0);
		
		/*
		 * Done with the Data-Out. Next, check if we need
		 * to send another unsolicited Data-Out.
		 */
		if (ctask->unsol_count) {
			ctask->xmstate |= XMSTATE_UNS_INIT;
			goto _unsolicit_head_again;
		}
		//BUG_ON(ctask->xmstate != XMSTATE_IDLE);
		return 0;
	}






	if (ctask->xmstate & XMSTATE_SOL_HDR) {
		ctask->xmstate &= ~XMSTATE_SOL_HDR;
		ctask->xmstate |= XMSTATE_SOL_DATA;
		if (!ctask->r2t) 
		{
			//__kfifo_get(ctask->r2tqueue, (void*)&r2t, sizeof(void*));
			r2t = malloc(sizeof(struct iscsi_r2t_info));
			ctask->r2t = r2t;
		}		
_solicit_head_again:
		//BUG_ON(r2t == NULL);
		if (kiscsi_sendhdr(conn, &r2t->headbuf)) {
			ctask->xmstate &= ~XMSTATE_SOL_DATA;
			ctask->xmstate |= XMSTATE_SOL_HDR;
			return -EAGAIN;
		}
		//debug_scsi("sol dout [dsn %d itt 0x%x dlen %d sent %d]\n", r2t->solicit_datasn - 1, ctask->itt, r2t->data_count, r2t->sent);
		printf("sol dout [dsn %d itt 0x%x dlen %d sent %d]\n", r2t->solicit_datasn - 1, ctask->itt, r2t->data_count, r2t->sent);
	}





	if (ctask->xmstate & XMSTATE_SOL_DATA) {
		int left;
		ctask->xmstate &= ~XMSTATE_SOL_DATA;
		r2t = ctask->r2t;
_solicit_again:
		/*
		 * send Data-Out whitnin this R2T sequence.
		 */
		if (r2t->data_count) {
			if (kiscsi_sendpage(conn, &r2t->sendbuf, &r2t->data_count,&r2t->sent)) 
			{
				ctask->xmstate |= XMSTATE_SOL_DATA;
				/* will continue with this ctask later.. */
				return -EAGAIN;
			}
			//BUG_ON(r2t->data_count < 0);
			if (r2t->data_count) {
				//BUG_ON(ctask->bad_sg == r2t->sg);
				//BUG_ON(ctask->sc->use_sg == 0);
				if (!iscsi_buf_left(&r2t->sendbuf)) 
				{
					//iscsi_buf_init_sg(&r2t->sendbuf, r2t->sg);
					//r2t->sg += 1;
				}
				goto _solicit_again;
			}
		}
		/*
		 * Done with this Data-Out. Next, check if we have
		 * to send another Data-Out for this R2T.
		 */
		//BUG_ON(r2t->data_length - r2t->sent < 0);
		left = r2t->data_length - r2t->sent;
		if (left) {
			iscsi_solicit_data_cont(conn, ctask, r2t, left);
			ctask->xmstate |= XMSTATE_SOL_DATA;
			goto _solicit_head_again;
		}

		/*
		 * Done with this R2T. Check if there are more
		 * outstanding R2Ts ready to be processed.
		 */
		//BUG_ON(ctask->r2t_data_count - r2t->data_length < 0);
		ctask->r2t_data_count -= r2t->data_length;
		ctask->r2t = NULL;
		//__kfifo_put(ctask->r2tpool.queue, (void*)&r2t, sizeof(void*));
		free(r2t);
		//if (__kfifo_get(ctask->r2tqueue, (void*)&r2t, sizeof(void*))) 		
		//{
		//	ctask->r2t = r2t;
		//	ctask->xmstate |= XMSTATE_SOL_DATA;
		//	goto _solicit_head_again;
		//}
	}

	//BUG_ON(ctask->xmstate != XMSTATE_IDLE);

	//kiscsi_tcp_data_recv(conn);

	return 0;
}








/*
 * Allocate a new connection within the session and bind it to
 * the given socket.
 */
//static iscsi_cnx_h iscsi_conn_create(iscsi_snx_h snxh, iscsi_cnx_h handle, uint32_t conn_idx)
iscsi_cnx_h kiscsi_conn_create(iscsi_snx_h snxh, iscsi_cnx_h handle, uint32_t conn_idx)
{
	struct iscsi_session *session = iscsi_ptr(snxh);
	struct iscsi_conn *conn = NULL;

	//conn = kmalloc(sizeof(struct iscsi_conn), GFP_KERNEL);
	conn = cvmx_bootmem_alloc(sizeof(struct iscsi_conn), CVMX_CACHE_LINE_SIZE);
	printf("iscsi conn is %p\n", conn);
	if (conn == NULL)
		goto conn_alloc_fault;
	memset(conn, 0, sizeof(struct iscsi_conn));

	memset(conn->itt_queue, 0, ITTLENGTH * sizeof(struct itt_work *));
        conn->cn_itt = 0;

	conn->c_stage = ISCSI_CNX_INITIAL_STAGE;
	conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	conn->in_progress_xmit = IN_PROGRESS_XMIT_SCSI;
	conn->id = conn_idx;
	conn->exp_statsn = 0;
	conn->handle = handle;
	conn->tmabort_state = TMABORT_INITIAL;

	/* initial operational parameters */
	conn->hdr_size = sizeof(struct iscsi_hdr);
	conn->max_recv_dlength = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;

	//spin_lock_init(&conn->lock);

	/* initialize general xmit PDU commands queue */
	//conn->xmitqueue = kfifo_alloc(session->cmds_max * sizeof(void*),
	//				GFP_KERNEL, NULL);
	//if (conn->xmitqueue == ERR_PTR(-ENOMEM))
	//	goto xmitqueue_alloc_fault;

	/* initialize write response PDU commands queue */
	//conn->writequeue = kfifo_alloc(session->cmds_max * sizeof(void*),
	//				GFP_KERNEL, NULL);
	//if (conn->writequeue == ERR_PTR(-ENOMEM))
	//	goto writequeue_alloc_fault;

	/* initialize general immediate PDU commands queue */
	//conn->immqueue = kfifo_alloc(session->imm_max * sizeof(void*),
	//				GFP_KERNEL, NULL);
	//if (conn->immqueue == ERR_PTR(-ENOMEM))
	//	goto immqueue_alloc_fault;
	//
	//

	//INIT_WORK(&conn->xmitwork, iscsi_xmitworker, conn);


	/* allocate login_mtask used for initial login/text sequence */
	//spin_lock_bh(&session->lock);
	//if (!__kfifo_get(session->immpool.queue, (void*)&conn->login_mtask, sizeof(void*))) 
	//{
		//spin_unlock_bh(&session->lock);
	//	goto login_mtask_alloc_fault;
	//}
	//spin_unlock_bh(&session->lock);

	// __kfifo_get
	conn->login_mtask = cvmx_bootmem_alloc(sizeof(struct iscsi_mgmt_task), CVMX_CACHE_LINE_SIZE);

	/* allocate initial PDU receive place holder */
	//if (conn->max_recv_dlength <= PAGE_SIZE)
		//conn->data = kmalloc(conn->max_recv_dlength, GFP_KERNEL);
	//	conn->data = malloc(conn->max_recv_dlength);
	//else
	//	conn->data = (void*)__get_free_pages(GFP_KERNEL, get_order(conn->max_recv_dlength));

	conn->data = cvmx_bootmem_alloc(conn->max_recv_dlength, CVMX_CACHE_LINE_SIZE);

	if (!conn->data)
		goto max_recv_dlenght_alloc_fault;

	//init_timer(&conn->tmabort_timer);
	//init_MUTEX(&conn->xmitsema);
	//init_waitqueue_head(&conn->ehwait);

	return iscsi_handle(conn);

max_recv_dlenght_alloc_fault:
	//spin_lock_bh(&session->lock);
	//__kfifo_put(session->immpool.queue, (void*)&conn->login_mtask,
	//	    sizeof(void*));
	free(conn->login_mtask);
	//spin_unlock_bh(&session->lock);
login_mtask_alloc_fault:
	//kfifo_free(conn->immqueue);
immqueue_alloc_fault:
	//kfifo_free(conn->writequeue);
writequeue_alloc_fault:
	//kfifo_free(conn->xmitqueue);
xmitqueue_alloc_fault:
	//kfree(conn);
conn_alloc_fault:
	return iscsi_handle(NULL);
}




















int kiscsi_conn_bind(iscsi_snx_h snxh, iscsi_cnx_h cnxh, uint32_t transport_fd, int is_leading)
{
	struct iscsi_session *session = iscsi_ptr(snxh);
	struct iscsi_conn *conn = iscsi_ptr(cnxh);

	int socket_fd = transport_fd;
	//struct sock *sk;
	//struct socket *sock;
	int err;

	//if (!(sock = sockfd_lookup(transport_fd, &err))) 
	//{
	//	printk("iSCSI: sockfd_lookup failed %d\n", err);
	//	return -EEXIST;
	//}

	/* bind iSCSI connection and socket */
	conn->socket = socket_fd;

	/* setup Socket parameters */
	//sk = sock->sk;
	//sk->sk_reuse = 1;
	//sk->sk_sndtimeo = 15 * HZ; /* FIXME: make it configurable */
	//sk->sk_allocation = GFP_ATOMIC;

	/* FIXME: disable Nagle's algorithm */

	/* Intercept TCP callbacks for sendfile like receive processing. */
	//iscsi_conn_set_callbacks(conn);

	/*
	 * bind new iSCSI connection to session
	 */
	conn->session = session;

	//spin_lock_bh(&session->conn_lock);
	//list_add(&conn->item, &session->connections);
	//spin_unlock_bh(&session->conn_lock);

	if (is_leading)
		session->leadconn = conn;

	return 0;
}






 int
kiscsi_conn_start(iscsi_cnx_h cnxh)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	if (session == NULL) {
		printf("kiscsi_conn_start: iSCSI: can't start not-binded connection\n");
		return -EPERM;
	}

	if (session->state == ISCSI_STATE_LOGGED_IN && session->leadconn == conn) 
	{
		scsi_scan_host(session->host);
		printf("kiscsi_conn_start: scsi_scan_host done! \n");
	}

	//spin_lock_bh(&session->lock);
	conn->c_stage = ISCSI_CNX_STARTED;
	//conn->cpu = session->conn_cnt % num_online_cpus();
	session->state = ISCSI_STATE_LOGGED_IN;
	session->conn_cnt++;
	//spin_unlock_bh(&session->lock);

	return 0;
}



//static int iscsi_send_pdu(iscsi_cnx_h cnxh, struct iscsi_hdr *hdr, char *data, uint32_t data_size)
int kiscsi_send_pdu(iscsi_cnx_h cnxh, struct iscsi_hdr *hdr, char *data, uint32_t data_size)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;
	struct iscsi_mgmt_task *mtask;
	char *pdu_data = NULL;

	/* FIXME: non-immediate control commands are not supported yet */
	//BUG_ON(!(hdr->opcode & ISCSI_OP_IMMEDIATE));

	if (data_size) 
	{
		//pdu_data = kmalloc(data_size, GFP_KERNEL);
		pdu_data = malloc(data_size);
		if (!pdu_data)
			return -ENOMEM;
	}

	//spin_lock_bh(&session->lock);
	if (conn->c_stage != ISCSI_CNX_INITIAL_STAGE) 
	{
		int exp_statsn;

		//if (!__kfifo_get(session->immpool.queue, (void*)&mtask, sizeof(void*))) 
		mtask = malloc(sizeof(struct iscsi_mgmt_task));
		//{
			//spin_unlock_bh(&session->lock);
		//	return -ENOSPC;
		//}

		/*
		 * Check previous ExpStatSN. Free associated resources.
		 */

		// ?
		exp_statsn = ((struct iscsi_nopout*)&mtask->hdr)->exp_statsn;
		
		if ((int)(conn->exp_statsn - exp_statsn) <= 0) 
		{
			if (mtask->data) {
				free(mtask->data);
				mtask->data = NULL;
				mtask->data_count = 0;
			}
		}
		printf("not ISCSI_CNX_INITIAL_STAGE\n");
	} 
	else 
	{
		printf("ISCSI_CNX_INITIAL_STAGE\n");
		/*
		 * Preserve ITT for all requests within this
		 * login or text negotiation sequence. Note that mtask is
		 * preallocated at cnx_create() and will be released
		 * at cnx_start() or cnx_destroy().
		 */
		mtask = conn->login_mtask;
	}

	printf("hdr->itt = 0x%x\n", hdr->itt);
	printf("mtask->itt = 0x%x\n", mtask->itt);

	//hdr->itt = 0x1008;
	//mtask->itt = 0x1009;
	
	/*
	 * pre-format CmdSN and ExpStatSN for outgoing PDU.
	 */
	if (hdr->itt != ISCSI_RESERVED_TAG) 
	{
		// hdr->itt = htonl(mtask->itt);
		hdr->itt = mtask->itt;
		
		//((struct iscsi_nopout*)hdr)->cmdsn = htonl(session->cmdsn);
		((struct iscsi_nopout*)hdr)->cmdsn = session->cmdsn;

		if (conn->c_stage == ISCSI_CNX_STARTED) 
		{
			session->cmdsn++;
		}
	} 
	else 
	{
		/* do not advance CmdSN */
		//((struct iscsi_nopout*)hdr)->cmdsn = htonl(session->cmdsn);
		((struct iscsi_nopout*)hdr)->cmdsn = session->cmdsn;
	}

	
	//((struct iscsi_nopout*)hdr)->exp_statsn = htonl(conn->exp_statsn);
	((struct iscsi_nopout*)hdr)->exp_statsn = conn->exp_statsn;

	memcpy(&mtask->hdr, hdr, sizeof(struct iscsi_hdr));

	if (conn->c_stage != ISCSI_CNX_INITIAL_STAGE) 
	{
		//iscsi_buf_init_hdr(conn, &mtask->headbuf, (char*)&mtask->hdr, (u8 *)mtask->hdrext);
		
		//mtask->headbuf = &mtask->hdr;
		//mtask->headbuf_length = sizeof(struct iscsi_hdr);
		//mtask->headbuf_offset = 0;
		//mtask->headbuf_sent = 0;

		mtask->headbuf.buffer = &mtask->hdr;
		mtask->headbuf.length = sizeof(struct iscsi_hdr);
		mtask->headbuf.offset = 0;
		mtask->headbuf.sent = 0;
	} 
	else 
	{
		//iscsi_buf_init_virt(&mtask->headbuf, (char*)&mtask->hdr,
		//		    sizeof(struct iscsi_hdr));
		/*
		mtask->headbuf = &mtask->hdr;
		mtask->headbuf_length = sizeof(struct iscsi_hdr);
		mtask->headbuf_offset = 0;
		mtask->headbuf_sent = 0;
		*/
		mtask->headbuf.buffer = &mtask->hdr;
		mtask->headbuf.length = sizeof(struct iscsi_hdr);
		mtask->headbuf.offset = 0;
		mtask->headbuf.sent = 0;
	}
	//spin_unlock_bh(&session->lock);

	if (mtask->data) {
		free(mtask->data);
		mtask->data = NULL;
		mtask->data_count = 0;
	}

	if (data_size) {
		memcpy(pdu_data, data, data_size);
		mtask->data = pdu_data;
		mtask->data_count = data_size;
	}

	mtask->xmstate = XMSTATE_IMM_HDR;

	if (mtask->data_count) 
	{
		// iscsi_buf_init_virt(&mtask->sendbuf, (char*)mtask->data, mtask->data_count);
		//mtask->sendbuf = mtask->data;
		//mtask->sendbuf_length = mtask->data_count;
		//mtask->sendbuf_offset = 0;
		//mtask->sendbuf_sent = 0;
		
		mtask->sendbuf.buffer = mtask->data;
		mtask->sendbuf.length = mtask->data_count;
		mtask->sendbuf.offset = 0;
		mtask->sendbuf.sent = 0;
		
		/* FIXME: implement: convertion of mtask->data into 1st
		 *        mtask->sendbuf. Keep in mind that virtual buffer
		 *        could be spreaded accross multiple pages... */
		 
		//if(mtask->sendbuf.sg.offset + mtask->data_count > PAGE_SIZE) 
		//{
		//	if (conn->c_stage == ISCSI_CNX_STARTED) {
				//spin_lock_bh(&session->lock);
		//		__kfifo_put(session->immpool.queue,
		//			    (void*)&mtask, sizeof(void*));				
				//spin_unlock_bh(&session->lock);
		//	}
		//	return -ENOMEM;
		//}
	}

	//debug_scsi("immpdu [op 0x%x itt 0x%x datalen %d]\n",
	//	   hdr->opcode, ntohl(hdr->itt), data_size);
	printf("kscsi_send_pdu:  immpdu [op 0x%x itt 0x%x datalen %d]\n", hdr->opcode, hdr->itt, data_size);
	// __kfifo_put(conn->immqueue, (void*)&mtask, sizeof(void*));
	// schedule_work(&conn->xmitwork);

       conn->mtask = mtask; 
	kiscsi_xmitworker((void *)conn);
	//kiscsi_tcp_data_recv(conn);
	return 0;
}




iscsi_snx_h
kiscsi_session_create(iscsi_snx_h handle, uint32_t initial_cmdsn,
		     uint32_t *host_no)
{
	int cmd_i;
	struct iscsi_session *session;
	struct Scsi_Host *host;
	int res;
	//printf("111\n");
	/* FIXME: verify "unique-ness" of the session's handle */

	host = scsi_host_alloc(&iscsi_sht, sizeof(struct iscsi_session));
	
	if (host == NULL) {
		printf("can not allocate SCSI host for session %p\n", iscsi_ptr(handle));
		goto host_alloc_fault;
	}
	//printf("112\n");
	host->max_id = 1;
	host->max_channel = 0;
	
	session = (struct iscsi_session *)host->hostdata;
	//printf("114\n");
	memset(session, 0, sizeof(struct iscsi_session));
	//add by gxy
	printf("iscsi session is %p\n", session);
	session->context = ((uiscsi_session_t *)handle)->context;
	*host_no = session->id = host->host_no;
	//printf("115\n");
	session->host = host;
	session->state = ISCSI_STATE_LOGGED_IN;
	session->imm_max = ISCSI_IMM_CMDS_MAX;
	session->cmds_max = ISCSI_XMIT_CMDS_MAX;
	session->cmdsn = initial_cmdsn;
	session->exp_cmdsn = initial_cmdsn + 1;
	session->max_cmdsn = initial_cmdsn + 1;
	session->handle = handle;
	session->max_r2t = 1;
	//printf("116\n");

	/* initialize SCSI PDU commands pool */
	//if (iscsi_pool_init(&session->cmdpool, session->cmds_max, (void***)&session->cmds, sizeof(struct iscsi_cmd_task))) 
	//{
	//	goto cmdpool_alloc_fault;
	//}
		
	 session->cmds = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	/* pre-format cmds pool with ITT */
	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) 
	{
		session->cmds[cmd_i] = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
		session->cmds[cmd_i]->itt = cmd_i;
	}
	

	//spin_lock_init(&session->lock);
	//spin_lock_init(&session->conn_lock);
	//INIT_LIST_HEAD(&session->connections);

	/* initialize immediate command pool */
	//if (iscsi_pool_init(&session->immpool, session->imm_max, (void***)&session->imm_cmds, sizeof(struct iscsi_mgmt_task))) 
	//{
	//	goto immpool_alloc_fault;
	//}
	/* pre-format immediate cmds pool with ITT */

	session->imm_cmds = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	for (cmd_i = 0; cmd_i < session->imm_max; cmd_i++) 
	{
		session->imm_cmds[cmd_i] = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);		
		session->imm_cmds[cmd_i]->itt = ISCSI_IMM_ITT_OFFSET + cmd_i;
	}
	//printf("117\n");

	if (iscsi_r2tpool_alloc(session))
		goto r2tpool_alloc_fault;
	//
	//printf("118\n");
	//res = scsi_add_host(host, NULL);
	res = scsi_add_host(host);
	if (res) {
		printf("can not add host_no %d (%d)\n", *host_no, res);
		goto add_host_fault;
	}
	//printf("119\n");
	return iscsi_handle(session);

add_host_fault:
	//iscsi_r2tpool_free(session);
r2tpool_alloc_fault:
	//iscsi_pool_free(&session->immpool, (void**)session->imm_cmds);
immpool_alloc_fault:
	//iscsi_pool_free(&session->cmdpool, (void**)session->cmds);
cmdpool_alloc_fault:
	//scsi_host_put(host);
host_alloc_fault:
	*host_no = -1;
	return iscsi_handle(NULL);
}






int
kiscsi_set_param(iscsi_cnx_h cnxh, iscsi_param_e param, uint32_t value)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	if (conn->c_stage == ISCSI_CNX_INITIAL_STAGE) 
	{
		switch(param) 
		{
		case ISCSI_PARAM_MAX_RECV_DLENGTH: 
		{
			//char *saveptr = conn->data;

			//if (value <= PAGE_SIZE)
				//conn->data = kmalloc(value, GFP_KERNEL);
			//	conn->data = malloc(value);
			//else
				//conn->data = (void*)__get_free_pages(GFP_KERNEL, get_order(value));

			//if (conn->data == NULL) 
			//{
			//	conn->data = saveptr;
			//	return -ENOMEM;
			//}
			
			//if (conn->max_recv_dlength <= PAGE_SIZE)
			//	kfree(saveptr);
			//else
			//	free_pages((unsigned long)saveptr, get_order(conn->max_recv_dlength));
			printf("kiscsi_set_param:  conn->max_recv_dlength = value = %u \n", value);
			conn->max_recv_dlength = value;
		}
		break;
		case ISCSI_PARAM_MAX_XMIT_DLENGTH:
			conn->max_xmit_dlength = value;
			break;
		case ISCSI_PARAM_HDRDGST_EN:
			conn->hdrdgst_en = value;
			conn->hdr_size = sizeof(struct iscsi_hdr);
			/*if (conn->hdrdgst_en) 
			{
				conn->hdr_size += sizeof(__u32);
				if (!conn->tx_tfm)
					conn->tx_tfm =
						crypto_alloc_tfm("crc32c", 0);
				if (!conn->tx_tfm)
					return -ENOMEM;
				if (!conn->rx_tfm)
					conn->rx_tfm =
						crypto_alloc_tfm("crc32c", 0);
				if (!conn->rx_tfm) {
					crypto_free_tfm(conn->tx_tfm);
					return -ENOMEM;
				}
			} else {
				if (conn->tx_tfm)
					crypto_free_tfm(conn->tx_tfm);
				if (conn->rx_tfm)
					crypto_free_tfm(conn->rx_tfm);
			}*/
			break;
		case ISCSI_PARAM_DATADGST_EN:
			if (conn->datadgst_en)
				return -EPERM;
			conn->datadgst_en = value;
			break;
		case ISCSI_PARAM_INITIAL_R2T_EN:
			session->initial_r2t_en = value;
			break;
		case ISCSI_PARAM_MAX_R2T:
			//iscsi_r2tpool_free(session);
			session->max_r2t = value;
			//if (session->max_r2t & (session->max_r2t - 1)) {
			//	session->max_r2t =
			//		roundup_pow_of_two(session->max_r2t);
			//}
			//if (iscsi_r2tpool_alloc(session))
			//	return -ENOMEM;
			break;
		case ISCSI_PARAM_IMM_DATA_EN:
			session->imm_data_en = value;
			break;
		case ISCSI_PARAM_FIRST_BURST:
			session->first_burst = value;
			break;
		case ISCSI_PARAM_MAX_BURST:
			session->max_burst = value;
			break;
		case ISCSI_PARAM_PDU_INORDER_EN:
			session->pdu_inorder_en = value;
			break;
		case ISCSI_PARAM_DATASEQ_INORDER_EN:
			session->dataseq_inorder_en = value;
			break;
		case ISCSI_PARAM_ERL:
			session->erl = value;
			break;
		case ISCSI_PARAM_IFMARKER_EN:
			session->ifmarker_en = value;
			break;
		case ISCSI_PARAM_OFMARKER_EN:
			session->ifmarker_en = value;
			break;
		default:
			break;
		}
	}
	else {
		printf("iSCSI: can not change parameter [%d]\n", param);
	}

	return 0;
}





#ifdef CMD




/*
 * Terminate connection queues, free all associated resources.
 */
static void
iscsi_conn_destroy(iscsi_cnx_h cnxh)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	BUG_ON(conn->sock == NULL);

	sock_hold(conn->sock->sk);
	iscsi_conn_restore_callbacks(conn);
	sock_put(conn->sock->sk);
	sock_release(conn->sock);

	del_timer_sync(&conn->tmabort_timer);
	if (session->leadconn == conn) {
		/*
		 * Control plane decided to destroy leading connection?
		 * Its a signal for us to give up on recovery.
		 */
		session->state = ISCSI_STATE_TERMINATE;
		wake_up(&conn->ehwait);
	}

	/*
	 * Block control plane caller (a thread coming from
	 * a user space) until all the in-progress commands for this connection
	 * time out or fail.
	 * We must serialize with xmitwork recv pathes.
	 */
	down(&conn->xmitsema);
	conn->c_stage = ISCSI_CNX_CLEANUP_WAIT;
	while (1) {
		spin_lock_bh(&conn->lock);
		if (!session->host->host_busy) { /* OK for ERL == 0 */
			spin_unlock_bh(&conn->lock);
			break;
		}
		spin_unlock_bh(&conn->lock);
		msleep_interruptible(500);
	}
	up(&conn->xmitsema);

	/* now free crypto */
	if (conn->hdrdgst_en || conn->datadgst_en) {
		if (conn->tx_tfm)
			crypto_free_tfm(conn->tx_tfm);
		if (conn->rx_tfm)
			crypto_free_tfm(conn->rx_tfm);
	}

	/* free conn->data, size = MaxRecvDataSegmentLength */
	if (conn->max_recv_dlength <= PAGE_SIZE)
		kfree(conn->data);
	else
		free_pages((unsigned long)conn->data,
					get_order(conn->max_recv_dlength));

	spin_lock_bh(&session->lock);
	__kfifo_put(session->immpool.queue, (void*)&conn->login_mtask,
		    sizeof(void*));
	spin_unlock_bh(&session->lock);

	kfifo_free(conn->xmitqueue);
	kfifo_free(conn->writequeue);
	kfifo_free(conn->immqueue);

	spin_lock_bh(&session->conn_lock);
	list_del(&conn->item);
	if (list_empty(&session->connections))
		session->leadconn = NULL;
	if (session->leadconn && session->leadconn == conn)
		session->leadconn = container_of(session->connections.next,
			struct iscsi_conn, item);
	spin_unlock_bh(&session->conn_lock);

	if (session->leadconn == NULL) {
		/* non connections exits.. reset sequencing */
		session->cmdsn = session->max_cmdsn = session->exp_cmdsn = 1;
	}

	kfree(conn);
}





static void
iscsi_conn_stop(iscsi_cnx_h cnxh)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	spin_lock_bh(&session->lock);
	conn->c_stage = ISCSI_CNX_STOPPED;
	conn->suspend = 1;
	session->conn_cnt--;

	if (session->conn_cnt == 0 ||
	    session->leadconn == conn) {
		session->state = ISCSI_STATE_FAILED;
	}
	spin_unlock_bh(&session->lock);
}
















static void
iscsi_tmabort_timedout(unsigned long data)
{
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *)data;
	struct iscsi_conn *conn = ctask->conn;

	conn->tmabort_state = TMABORT_TIMEDOUT;
	debug_scsi("tmabort timedout [sc %lx itt 0x%x]\n", (long)ctask->sc,
		   ctask->itt);
}

static int
iscsi_eh_abort(struct scsi_cmnd *sc)
{
	int rc;
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *)sc->SCp.ptr;
	struct iscsi_conn *conn = ctask->conn;
	struct iscsi_session *session = conn->session;

	spin_unlock_irq(session->host->host_lock);

	debug_scsi("aborting [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);

	/*
	 * two cases for ERL=0 here:
	 *
	 * 1) connection-level failure;
	 * 2) recovery due protocol error;
	 */
	if (session->state != ISCSI_STATE_LOGGED_IN) {
		if (session->state == ISCSI_STATE_TERMINATE)
			goto failed;
	} else {
		struct iscsi_tm *hdr = &conn->tmhdr;

		/*
		 * ctask timed out but session is OK
		 * ERL=0 requires task mgmt abort to be issued on each
		 * failed command. requests must be serialized.
		 */
		memset(hdr, 0, sizeof(struct iscsi_tm));
		hdr->opcode = ISCSI_OP_SCSI_TMFUNC | ISCSI_OP_IMMEDIATE;
		hdr->flags = ISCSI_TM_FUNC_ABORT_TASK;
		hdr->flags |= ISCSI_FLAG_CMD_FINAL;
		memcpy(hdr->lun, ctask->hdr.lun, 8);
		hdr->rtt = ctask->hdr.itt;
		hdr->refcmdsn = ctask->hdr.cmdsn;

		conn->tmabort_state = TMABORT_INITIAL;

		rc = iscsi_send_pdu(iscsi_handle(conn),
			    (struct iscsi_hdr *)hdr, NULL, 0);
		if (rc) {
			session->state = ISCSI_STATE_FAILED;
			iscsi_control_cnx_error(conn->handle,
				ISCSI_ERR_CNX_FAILED);
			debug_scsi("abort sent failure [itt 0x%x]", ctask->itt);
		} else {
			conn->tmabort_timer.expires = 3*HZ + jiffies; /*3 secs*/
			conn->tmabort_timer.function = iscsi_tmabort_timedout;
			conn->tmabort_timer.data = (unsigned long)ctask;
			add_timer(&conn->tmabort_timer);
			debug_scsi("abort sent [itt 0x%x]", ctask->itt);
		}
	}


	/*
	 * block eh thread until:
	 *
	 * 1) abort response;
	 * 2) abort timeout;
	 * 3) session re-opened;
	 * 4) session terminated;
	 */
	while (1) {
		int p_state = session->state;
		rc = wait_event_interruptible(conn->ehwait,
			(p_state == ISCSI_STATE_LOGGED_IN ?
			 (session->state == ISCSI_STATE_TERMINATE ||
			  conn->tmabort_state != TMABORT_INITIAL) :
			 (session->state == ISCSI_STATE_TERMINATE ||
			  session->state == ISCSI_STATE_LOGGED_IN)));
		if (rc) {
			/* shutdown.. */
			session->state = ISCSI_STATE_TERMINATE;
			goto failed;
		}

		if (signal_pending(current))
			flush_signals(current);

		if (session->state == ISCSI_STATE_TERMINATE)
			goto failed;

		if (conn->tmabort_state == TMABORT_TIMEDOUT ||
		    conn->tmabort_state == TMABORT_FAILED) {
			conn->tmabort_state = TMABORT_INITIAL;
			session->state = ISCSI_STATE_FAILED;
			iscsi_control_cnx_error(conn->handle,
				ISCSI_ERR_CNX_FAILED);
			continue;
		}

		break;
	}

	debug_scsi("abort success [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);
	BUG_ON(session->state != ISCSI_STATE_LOGGED_IN);
	spin_lock_irq(session->host->host_lock);
	return SUCCESS;
failed:
	iscsi_ctask_cleanup(conn, ctask);
	debug_scsi("abort failed [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);
	spin_lock_irq(session->host->host_lock);
	return FAILED;
}
//
//
//
//
//
//
//
///
//

static void
iscsi_r2tpool_free(struct iscsi_session *session)
{
	int i;

	for (i = 0; i < session->cmds_max; i++) {
		mempool_destroy(session->cmds[i]->datapool);
		kfifo_free(session->cmds[i]->r2tqueue);
		iscsi_pool_free(&session->cmds[i]->r2tpool,
				(void**)session->cmds[i]->r2ts);
	}
}


//
//
//
//
//
//
//
//



// 




static void
iscsi_session_destroy(iscsi_snx_h snxh)
{/*
	int cmd_i;
	struct iscsi_data_task *dtask, *n;
	struct iscsi_session *session = iscsi_ptr(snxh);

	scsi_remove_host(session->host);

	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) {
		struct iscsi_cmd_task *ctask = session->cmds[cmd_i];
		list_for_each_entry_safe(dtask, n, &ctask->dataqueue, item) {
			list_del(&dtask->item);
			mempool_free(dtask, ctask->datapool);
		}
	}

	for (cmd_i = 0; cmd_i < session->imm_max; cmd_i++) {
		if (session->imm_cmds[cmd_i]->data)
			kfree(session->imm_cmds[cmd_i]->data);
	}

	iscsi_r2tpool_free(session);
	iscsi_pool_free(&session->immpool, (void**)session->imm_cmds);
	iscsi_pool_free(&session->cmdpool, (void**)session->cmds);
	scsi_host_put(session->host);*/
}














/*
struct iscsi_transport iscsi_tcp_transport = {
	.name                   = "tcp",
	.destroy_session        = iscsi_session_destroy,
	.create_cnx             = iscsi_conn_create,
	.bind_cnx               = iscsi_conn_bind,
	.destroy_cnx            = iscsi_conn_destroy,
	.set_param              = iscsi_set_param,
	.start_cnx              = iscsi_conn_start,
	.stop_cnx               = iscsi_conn_stop,
	.send_pdu               = iscsi_send_pdu,
};



static int __init
iscsi_tcp_init(void)
{
	int error;

	taskcache = kmem_cache_create("iscsi_taskcache",
			sizeof(struct iscsi_data_task), 0, 0, NULL, NULL);
	if (!taskcache)
		return -ENOMEM;

	error = iscsi_register_transport(&iscsi_tcp_transport, 0);
	if (error)
		kmem_cache_destroy(taskcache);

	return error;
}

static void __exit
iscsi_tcp_exit(void)
{
	iscsi_unregister_transport(0);
	kmem_cache_destroy(taskcache);
}

module_init(iscsi_tcp_init);
module_exit(iscsi_tcp_exit);
*/



#endif




 int
iscsi_r2tpool_alloc(struct iscsi_session *session)
{
	int i;
	int cmd_i;

	/*
	 * initialize per-task: R2T pool and xmit queue
	 */
	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) 
	{
	        struct iscsi_cmd_task *ctask = session->cmds[cmd_i];

		/* R2T pool */
		//if (iscsi_pool_init(&ctask->r2tpool, session->max_r2t, (void***)&ctask->r2ts, sizeof(struct iscsi_r2t_info))) 
		//{
		//	goto r2t_alloc_fault;
		//}
		ctask->r2ts = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
		ctask->r2ts[cmd_i] = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);

		/* R2T xmit queue */
		//ctask->r2tqueue = kfifo_alloc(session->max_r2t * sizeof(void*), GFP_KERNEL, NULL);
		//if (ctask->r2tqueue == ERR_PTR(-ENOMEM)) {
		//	iscsi_pool_free(&ctask->r2tpool, (void**)ctask->r2ts);
		//	goto r2t_alloc_fault;
		//}

		/*
		 * number of
		 * Data-Out PDU's within R2T-sequence can be quite big;
		 * using mempool
		 */
		//ctask->datapool = mempool_create(ISCSI_DTASK_DEFAULT_MAX, mempool_alloc_slab, mempool_free_slab, taskcache);
		//if (ctask->datapool == NULL) {
		//	kfifo_free(ctask->r2tqueue);
		//	iscsi_pool_free(&ctask->r2tpool, (void**)ctask->r2ts);
		//	goto r2t_alloc_fault;
		//}
		//INIT_LIST_HEAD(&ctask->dataqueue);
	}

	return 0;

r2t_alloc_fault:
	//for (i = 0; i < cmd_i; i++) {
		//mempool_destroy(session->cmds[i]->datapool);
		//kfifo_free(session->cmds[i]->r2tqueue);
	//	iscsi_pool_free(&session->cmds[i]->r2tpool, (void**)session->cmds[i]->r2ts);
		
	//}
	return -ENOMEM;
}

