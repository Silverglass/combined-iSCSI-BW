/***********************************************************************

  OCTEON TOOLKITS                                                         
  Copyright (c) 2007 Cavium Networks. All rights reserved.

  This file, which is part of the OCTEON TOOLKIT from Cavium Networks,
  contains proprietary and confidential information of Cavium Networks
  and in some cases its suppliers.

  Any licensed reproduction, distribution, modification, or other use of
  this file or confidential information embodied in this file is subject
  to your license agreement with Cavium Networks. The applicable license
  terms can be found by contacting Cavium Networks or the appropriate
  representative within your company.

  All other use and disclosure is prohibited.

  Contact Cavium Networks at info@caviumnetworks.com for more information.

 ************************************************************************/ 

#ifndef __INICRMNGR_H__
#define __INICRMNGR_H__


/* UDP port number to used */
#define INIC_RMNGR_UDP_PORT                   8749
#define INIC_RMNGR_REQ_SIG   0xdeadbeef87654321ULL


/* request and response structures */

typedef struct _inic_rmngr_opcodes_t
{
    uint16_t major;
    uint16_t minor;
} __attribute__((packed)) inic_rmngr_opcodes_t;

typedef struct _inic_rmngr_request_t
{
    uint64_t              signature;
    inic_rmngr_opcodes_t  opcode;
    uint32_t              request_id;
    uint16_t              arg1;
    uint16_t              arg2;
    uint32_t              arg3;
} __attribute__((packed)) inic_rmngr_request_t;


typedef struct _inic_rmngr_response_t
{
    inic_rmngr_opcodes_t  opcode;
    uint32_t              request_id;
    uint16_t              response_code;
    uint16_t              unused1;
    uint32_t              unused2;
} __attribute__((packed)) inic_rmngr_response_t;




/*-------------------------------------------*/
/*-                                         -*/
/*  Opcodes and associated data structrues   */
/*-                                         -*/
/*-------------------------------------------*/


/*-------------------------------------------*/
/*            GET STATS = 1                  */
/*-------------------------------------------*/

/* MAJOR*/
#define INIC_RMNGR_MJAOR_GET_STATS      1

/* MINOR */
#define INIC_RMNGR_MINOR_TCP            1
#define INIC_RMNGR_MINOR_EXTRA          2


/* TCP stats */
typedef struct	_oct_inic_tcp_stats 
{
    uint32_t	tcps_connattempt;	/* connections initiated */
    uint32_t	tcps_accepts;		/* connections accepted */
    uint32_t	tcps_connects;		/* connections established */
    uint32_t	tcps_drops;		/* connections dropped */
    uint32_t	tcps_conndrops;		/* embryonic connections dropped */
    uint32_t	tcps_minmssdrops;	/* average minmss too low drops */
    uint32_t	tcps_closed;		/* conn. closed (includes drops) */
    uint32_t	tcps_segstimed;		/* segs where we tried to get rtt */
    uint32_t	tcps_rttupdated;	/* times we succeeded */
    uint32_t	tcps_delack;		/* delayed acks sent */
    uint32_t	tcps_timeoutdrop;	/* conn. dropped in rxmt timeout */
    uint32_t	tcps_rexmttimeo;	/* retransmit timeouts */
    uint32_t	tcps_persisttimeo;	/* persist timeouts */
    uint32_t	tcps_keeptimeo;		/* keepalive timeouts */
    uint32_t	tcps_keepprobe;		/* keepalive probes sent */
    uint32_t	tcps_keepdrops;		/* connections dropped in keepalive */

    uint32_t	tcps_sndtotal;		/* total packets sent */
    uint32_t	tcps_sndpack;		/* data packets sent */
    uint32_t	tcps_sndbyte;		/* data bytes sent */
    uint32_t	tcps_sndrexmitpack;	/* data packets retransmitted */
    uint32_t	tcps_sndrexmitbyte;	/* data bytes retransmitted */
    uint32_t	tcps_sndrexmitbad;	/* unnecessary packet retransmissions */
    uint32_t	tcps_sndacks;		/* ack-only packets sent */
    uint32_t	tcps_sndprobe;		/* window probes sent */
    uint32_t	tcps_sndurg;		/* packets sent with URG only */
    uint32_t	tcps_sndwinup;		/* window update-only packets sent */
    uint32_t	tcps_sndctrl;		/* control (SYN|FIN|RST) packets sent */

    uint32_t	tcps_rcvtotal;		/* total packets received */
    uint32_t	tcps_rcvpack;		/* packets received in sequence */
    uint32_t	tcps_rcvbyte;		/* bytes received in sequence */
    uint32_t	tcps_rcvbadsum;		/* packets received with ccksum errs */
    uint32_t	tcps_rcvbadoff;		/* packets received with bad offset */
    uint32_t	tcps_rcvmemdrop;	/* packets dropped for lack of memory */
    uint32_t	tcps_rcvshort;		/* packets received too short */
    uint32_t	tcps_rcvduppack;	/* duplicate-only packets received */
    uint32_t	tcps_rcvdupbyte;	/* duplicate-only bytes received */
    uint32_t	tcps_rcvpartduppack;	/* packets with some duplicate data */
    uint32_t	tcps_rcvpartdupbyte;	/* dup. bytes in part-dup. packets */
    uint32_t	tcps_rcvoopack;		/* out-of-order packets received */
    uint32_t	tcps_rcvoobyte;		/* out-of-order bytes received */
    uint32_t	tcps_rcvpackafterwin;	/* packets with data after window */
    uint32_t	tcps_rcvbyteafterwin;	/* bytes rcvd after window */
    uint32_t	tcps_rcvafterclose;	/* packets rcvd after "close" */
    uint32_t	tcps_rcvwinprobe;	/* rcvd window probe packets */
    uint32_t	tcps_rcvdupack;		/* rcvd duplicate acks */
    uint32_t	tcps_rcvacktoomuch;	/* rcvd acks for unsent data */
    uint32_t	tcps_rcvackpack;	/* rcvd ack packets */
    uint32_t	tcps_rcvackbyte;	/* bytes acked by rcvd acks */
    uint32_t	tcps_rcvwinupd;		/* rcvd window update packets */
    uint32_t	tcps_pawsdrop;		/* segments dropped due to PAWS */
    uint32_t	tcps_predack;		/* times hdr predict ok for acks */
    uint32_t	tcps_preddat;		/* times hdr predict ok for data pkts */
    uint32_t	tcps_usedrtt;		/* times RTT initialized from route */
    uint32_t	tcps_usedrttvar;	/* times RTTVAR initialized from rt */
    uint32_t	tcps_usedssthresh;	/* times ssthresh initialized from rt*/
    uint32_t	tcps_persistdrop;	/* timeout in persist state */
    uint32_t	tcps_badsyn;		/* bogus SYN, e.g. premature ACK */
    uint32_t	tcps_mturesent;		/* resends due to MTU discovery */
    uint32_t	tcps_listendrop;	/* listen queue overflows */
    uint32_t	tcps_badrst;		/* ignored RSTs in the window */

    uint32_t	tcps_sc_added;		/* entry added to syncache */
    uint32_t	tcps_sc_retransmitted;	/* syncache entry was retransmitted */
    uint32_t	tcps_sc_dupsyn;		/* duplicate SYN packet */
    uint32_t	tcps_sc_dropped;	/* could not reply to packet */
    uint32_t	tcps_sc_completed;	/* successful extraction of entry */
    uint32_t	tcps_sc_bucketoverflow;	/* syncache per-bucket limit hit */
    uint32_t	tcps_sc_cacheoverflow;	/* syncache cache limit hit */
    uint32_t	tcps_sc_reset;		/* RST removed entry from syncache */
    uint32_t	tcps_sc_stale;		/* timed out or listen socket gone */
    uint32_t	tcps_sc_aborted;	/* syncache entry aborted */
    uint32_t	tcps_sc_badack;		/* removed due to bad ACK */

    /* SACK related stats */
    uint32_t	tcps_sack_recovery_episode; /* SACK recovery episodes */
    uint32_t    tcps_sack_rexmits;	    /* SACK rexmit segments   */
    uint32_t    tcps_sack_rexmit_bytes;     /* SACK rexmit bytes      */	
    uint32_t    tcps_sack_rcv_blocks;       /* SACK blocks (options) received */
    uint32_t    tcps_sack_send_blocks;      /* SACK blocks (options) sent     */

}  __attribute__((packed)) oct_inic_tcp_stats_t ;



/* RESPONSE STRUCTRUES */
typedef struct _oct_inic_resp_tcp_stats_t
{
    inic_rmngr_response_t   response;
    oct_inic_tcp_stats_t    tcp_stats;

} __attribute__((packed)) oct_inic_resp_tcp_stats_t;




/*-------------------------------------------*/
/*              GET FPA = 2                  */
/*-------------------------------------------*/

/* MAJOR*/
#define INIC_RMNGR_MJAOR_GET_FPA        2

/* MINOR */
#define INIC_RMNGR_MINOR_ALLOC_COUNT    1
#define INIC_RMNGR_MINOR_CURRENT_COUNT  2


/* FPA ALLOC COUNT */
#define MAX_FPA_INFO_ENTRIES   5
#define MAX_FPA_POOLS          8

typedef struct _fpa_alloc_entry {
    uint64_t start_addr;
    uint64_t end_addr;
    uint64_t element_size;
    uint64_t info_base;
} __attribute__((packed)) fpa_alloc_entry_t;

typedef struct _fpa_alloc_info {
    int count;
    int unused;
    fpa_alloc_entry_t entry[MAX_FPA_INFO_ENTRIES];
} __attribute__((packed)) fpa_alloc_info_t;


/* RESPONSE STRUCTRUES */
typedef struct _oct_inic_resp_fpa_alloc_t
{
    inic_rmngr_response_t   response;
    fpa_alloc_info_t        fpa_alloc[MAX_FPA_POOLS];
} __attribute__((packed)) oct_inic_resp_fpa_alloc_t;


typedef struct _oct_inic_resp_fpa_current_t
{
    inic_rmngr_response_t   response;
    uint64_t                fpa_count[MAX_FPA_POOLS];
} __attribute__((packed)) oct_inic_resp_fpa_current_t;



/*-------------------------------------------*/
/*                 CSR = 3                   */
/*-------------------------------------------*/

/* MAJOR*/
#define INIC_RMNGR_MJAOR_CSR            3

/* MINOR */
#define INIC_RMNGR_MINOR_READ           1
#define INIC_RMNGR_MINOR_WRITE          2



/*-------------------------------------------*/
/*              DBG_LVL = 4                  */
/*-------------------------------------------*/

/* MAJOR */
#define INIC_RMNGR_MJAOR_DBG_LVL        4

/* MINOR */
#define INIC_RMNGR_MINOR_GET            1
#define INIC_RMNGR_MINOR_SET            2



/*-------------------------------------------*/
/*             ipfrag Test = 5               */
/*-------------------------------------------*/

/* MAJOR */
#define INIC_RMNGR_MAJOR_IPFRAG        5

/* MINOR */
#define INIC_RMNGR_MINOR_SETMTU        1





/* 
 * response code values 
 */
#define INIC_RMNGR_RESP_SUCCESS         0
#define INIC_RMNGR_INVALID_REQUEST      1
#define INIC_RMNGR_STATS_NOT_COLLECTED  2
#define INIC_RMNGR_NOT_IMPLEMENTED      3



#endif /* __INICRMNGR_H__ */
