/*
 * iSCSI Initiator TCP Transport
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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

#ifndef ISCSI_TCP_H
#define ISCSI_TCP_H



#include "iscsi_if.h"
#include "iscsi_proto.h"
#include "device.h"
#include "scsi.h"

/* Session's states */
#define ISCSI_STATE_FREE	1
#define ISCSI_STATE_LOGGED_IN	2
#define ISCSI_STATE_FAILED	3
#define ISCSI_STATE_TERMINATE	4

/* Connection's states */
#define ISCSI_CNX_INITIAL_STAGE		0
#define ISCSI_CNX_STARTED		1
#define ISCSI_CNX_STOPPED		2
#define ISCSI_CNX_CLEANUP_WAIT		3

/* Socket's Receive state machine */
#define IN_PROGRESS_WAIT_HEADER		0x0
#define IN_PROGRESS_HEADER_GATHER	0x1
#define IN_PROGRESS_DATA_RECV		0x2

/* Socket's Xmit state machine */
#define IN_PROGRESS_XMIT_IMM		0x0
#define IN_PROGRESS_XMIT_SCSI		0x1

/* Task Mgmt states */
#define	TMABORT_INITIAL			0x0
#define	TMABORT_SUCCESS			0x1
#define	TMABORT_FAILED			0x2
#define	TMABORT_TIMEDOUT		0x3

/* iSCSI Task Command's state machine */
#define IN_PROGRESS_IDLE		0x0
#define IN_PROGRESS_READ		0x1
#define IN_PROGRESS_WRITE		0x2

/* xmit state machine */
#define	XMSTATE_IDLE			0x0
#define	XMSTATE_R_HDR			0x1
#define	XMSTATE_W_HDR			0x2
#define	XMSTATE_IMM_HDR			0x4
#define	XMSTATE_IMM_DATA		0x8
#define	XMSTATE_UNS_INIT		0x10
#define	XMSTATE_UNS_HDR			0x20
#define	XMSTATE_UNS_DATA		0x40
#define	XMSTATE_SOL_HDR			0x80
#define	XMSTATE_SOL_DATA		0x100

#define ISCSI_DRV_VERSION	"0.1"
#define ISCSI_DEFAULT_PORT	3260
#define ISCSI_STRING_MAX	255
#define ISCSI_NODE_NAME_MAX	255
#define ISCSI_NODE_PORTAL_MAX	32
#define ISCSI_ALIAS_NAME_MAX	255
#define ISCSI_CONN_MAX		1
#define ISCSI_PORTAL_MAX	1
#define ISCSI_CONN_RCVBUF_MIN	262144
#define ISCSI_CONN_SNDBUF_MIN	262144
#define ISCSI_TEXT_SEPARATOR	'='
#define ISCSI_PAD_LEN		4
#define ISCSI_DRAFT20_VERSION	0x00
#define ISCSI_R2T_MAX		16
//#define ISCSI_XMIT_CMDS_MAX	64		/* must be power of 2 */
//#define ISCSI_IMM_CMDS_MAX	32		/* must be power of 2 */

#define ISCSI_XMIT_CMDS_MAX	64		/* must be power of 2 */
#define ISCSI_IMM_CMDS_MAX	32		/* must be power of 2 */


#define ISCSI_IMM_ITT_OFFSET	0x1000
#define ISCSI_SG_TABLESIZE	128
#define ISCSI_CMD_PER_LUN	128



//struct iscsi_queue {
//	struct kfifo		*queue;		/* FIFO Queue */
//	void			**pool;		/* Pool of elements */
//	int			max;		/* Max number of elements */
//};

#define ITTLENGTH 64
struct itt_work
{
	struct scsi_cmnd * sc;
};





struct iscsi_session;
struct iscsi_cmd_task;
struct iscsi_mgmt_task;



/* Socket connection recieve helper */
struct iscsi_tcp_recv {
	struct iscsi_hdr	*hdr;
	//struct sk_buff		*skb;

	char iscsi_skb[8192];
	
	int			offset;
	int			len;
	int			total_len;
	int			hdr_offset;
	int			copy;
	int			copied;
	int			padding;
	struct iscsi_cmd_task	*ctask;		/* current cmd in progress */

	/* copied and flipped values */
	int			opcode;
	int			flags;
	int			cmd_status;
	int			ahslen;
	int			datalen;
	uint32_t		itt;
};



struct iscsi_conn {

	struct itt_work * itt_queue[ITTLENGTH];
	int cn_itt;	//0~ITTLENGTH
	
	struct iscsi_hdr	hdr;		/* Header placeholder */
	char			hdrext[4*sizeof(unsigned short) + sizeof(unsigned int)];
	char			*data;		/* Data placeholder */
	int			data_copied;
	
	/* iSCSI connection-wide sequencing */
	uint32_t		exp_statsn;
	int			hdr_size;	/* PDU Header size pre-calc. */
	
	/* control data */
	int			senselen;	/* is data has sense? */
	int			cpu;		/* binded CPU */
	int			busy;
	int			id;		/* iSCSI CID */
	struct iscsi_tcp_recv	in;		/* TCP receive context */
	int			in_progress;	/* Connection state machine */
	int			in_progress_xmit; /* xmit state machine */

	int			ctask_in_progress;

	//struct socket           *sock;          /* BSD socket layer */
	
	int socket;
	struct iscsi_session	*session;	/* Parent session */

	
	//struct list_head	item;		/* item's list of connections */
	//struct kfifo		*writequeue;	/* Write response xmit queue */
	//struct kfifo		*immqueue;	/* Immediate xmit queue */
	//struct kfifo		*xmitqueue;	/* Data-path queue */
	//struct work_struct	xmitwork;	/* per-conn. xmit workqueue */
	
	volatile int		c_stage;	/* Connection state */
	iscsi_cnx_h		handle;		/* CP connection handle */
	struct iscsi_mgmt_task	*login_mtask;	/* mtask used for login/text */
	//spinlock_t		lock;		/* general connection lock */
	volatile int		suspend;	/* connection suspended */
	
	//struct crypto_tfm	*tx_tfm;
	//struct crypto_tfm	*rx_tfm;
	
	struct iscsi_mgmt_task	*mtask;		/* xmit mtask in progress */
	struct iscsi_cmd_task	*ctask;		/* xmit ctask in progress */
	
	//struct semaphore	xmitsema;
	//wait_queue_head_t	ehwait;
	struct iscsi_tm		tmhdr;
	volatile int		tmabort_state;
	//struct timer_list	tmabort_timer;
	//


	/* configuration */
	int			max_recv_dlength;
	int			max_xmit_dlength;
	int			hdrdgst_en;
	int			datadgst_en;
	//


	/* old values for socket callbacks */
	void			(*old_data_ready)(struct sock *, int);
	void			(*old_state_change)(struct sock *);
	void			(*old_write_space)(struct sock *);



	int recv_data_again;

  //Renjs
  int head_recv;
};





struct iscsi_session {
	//add by gxy
	uint64_t 	context;
	/* iSCSI session-wide sequencing */
	// �������
	uint32_t		cmdsn;
	uint32_t		exp_cmdsn;
	uint32_t		max_cmdsn;
	

	/* configuration */
	int			initial_r2t_en;
	int			max_r2t;
	int			imm_data_en;
	int			first_burst;
	int			max_burst;
	int			time2wait;
	int			time2retain;
	int			pdu_inorder_en;
	int			dataseq_inorder_en;
	int			erl;
	int			ifmarker_en;
	int			ofmarker_en;


	/* control data */
	struct Scsi_Host	*host;
	int			id;
	struct iscsi_conn	*leadconn;	/* Leading Conn. */
	//spinlock_t		conn_lock;
	//spinlock_t		lock;
	volatile int		state;
	//struct list_head	item;
	void			*auth_client;
	iscsi_snx_h		handle;		/* CP session handle */
	int			conn_cnt;

	//struct list_head	connections;	/* list of connects. */
	int			cmds_max;	/* size of cmds array */
	struct iscsi_cmd_task	**cmds;		/* Original Cmds arr */
	//struct iscsi_queue	cmdpool;	/* PDU's pool */
	int			imm_max;	/* size of Imm array */
	struct iscsi_mgmt_task	**imm_cmds;	/* Original Imm arr */
	//struct iscsi_queue	immpool;	/* Imm PDU's pool */
};




//



struct iscsi_buf {
	//struct scatterlist	sg;
	void *buffer;
	unsigned int offset;
	unsigned int length;
	unsigned int	sent;
};






struct iscsi_data_task {
	struct iscsi_data	hdr;			/* PDU */
	char			hdrext[sizeof(unsigned int)];	/* Header-Digest */
	struct list_head	item;			/* data queue item */
};




#define ISCSI_DTASK_DEFAULT_MAX	ISCSI_SG_TABLESIZE * PAGE_SIZE / 512

struct iscsi_mgmt_task {
	struct iscsi_hdr hdr;			/* mgmt. PDU */
	char		hdrext[sizeof(unsigned int)];	/* Header-Digest */
	char		*data;			/* mgmt payload */
	volatile int	xmstate;		/* mgmt xmit progress */
	int		data_count;		/* counts data to be sent */
	
	struct iscsi_buf headbuf;		/* Header Buffer */
	struct iscsi_buf sendbuf;		/* in progress buffer */

	/*
	void *headbuf;
	int headbuf_length;
	unsigned int headbuf_offset;
	unsigned int headbuf_sent;
	
	void *sendbuf;
	unsigned int sendbuf_length;
	unsigned int sendbuf_offset;
	unsigned int sendbuf_sent;*/
	
	int		sent;
	uint32_t	itt;			/* this ITT */
};

struct iscsi_r2t_info {
	uint32_t		ttt;		/* copied from R2T */
	uint32_t		exp_statsn;	/* copeid and incr. from R2T */
	int			data_length;	/* copied from R2T */
	int			data_offset;	/* copied from R2T */
	struct iscsi_buf	headbuf;	/* Data-Out Header Buffer */
	struct iscsi_buf	sendbuf;	/* Data-Out in progress buffer*/
	int			sent;		/* R2T sequence progress */
	int			data_count;	/* DATA-Out payload progress */
	//struct scatterlist	*sg;		/* per-R2T SG list */
	int			solicit_datasn;
};

struct iscsi_cmd_task {
	struct iscsi_cmd	hdr;			/* orig. SCSI PDU */
	char			hdrext[4*sizeof(unsigned short)+  sizeof(unsigned int)];		/* one AHS */
				  /* Header-Digest */
	int			itt;			/* this ITT */
	int			datasn;			/* DataSN numbering */
	struct iscsi_buf	headbuf;		/* Header Buffer */
	struct iscsi_buf	sendbuf;		/* in progress buffer */
	int			sent;
	//struct scatterlist	*sg;			/* per-cmd SG list */
	//struct scatterlist	*bad_sg;		/* assert statement */
	int			sg_count;		/* SG's to process */
	uint32_t		unsol_datasn;
	uint32_t		exp_r2tsn;
	volatile int		in_progress;		/* State machine */
	volatile int		xmstate;		/* Xmit State machine */
	int			imm_count;		/* Imm-Data bytes */
	int			unsol_count;		/* Imm-Data-Out bytes */
	int			r2t_data_count;		/* R2T Data-Out bytes */
	int			data_count;		/* Remaining Data-Out */
	struct scsi_cmnd	*sc;			/* Assoc. SCSI cmnd */
	int			total_length;
	int			data_offset;
	struct iscsi_conn	*conn;			/* used connection */

	struct iscsi_r2t_info	*r2t;			/* in progress R2T */
	//struct iscsi_queue	r2tpool;
	//struct kfifo		*r2tqueue;
	struct iscsi_r2t_info	**r2ts;
	//struct list_head	dataqueue;		/* Data-Out dataqueue */
	//mempool_t		*datapool;
};




// iscsi_tcp.c
extern iscsi_snx_h kiscsi_session_create(iscsi_snx_h handle, uint32_t initial_cmdsn, uint32_t *host_no);

extern iscsi_cnx_h kiscsi_conn_create(iscsi_snx_h snxh, iscsi_cnx_h handle, uint32_t conn_idx);

extern  int kiscsi_conn_bind(iscsi_snx_h snxh, iscsi_cnx_h cnxh, uint32_t transport_fd, int is_leading);

extern int kiscsi_conn_start(iscsi_cnx_h cnxh);

extern int kiscsi_send_pdu(iscsi_cnx_h cnxh, struct iscsi_hdr *hdr, char *data, uint32_t data_size);

extern  int kiscsi_set_param(iscsi_cnx_h cnxh, iscsi_param_e param, uint32_t value);

//extern  int kiscsi_set_param(iscsi_cnx_h cnxh, iscsi_param_e param, uint32_t value);

int kiscsi_tcp_data_recv(struct iscsi_conn *conn, struct scsi_cmnd * sc );


#endif /* ISCSI_H */









//Renjs
extern  int __send_nopin_rsp();
