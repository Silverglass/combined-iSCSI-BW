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

#include <stdio.h>

#include "global-config.h"
#include "cvmx-config.h"

#include "cvmx.h"
#include "cvmx-wqe.h"
#include "cvmx-pko.h"
#include "cvmx-spinlock.h"
#include "cvmx-helper.h"
#include "cvmx-malloc.h"
#include "cvmx-scratch.h"

#include "cvm-common-wqe.h"
#include "cvm-common-defs.h"
#include "cvm-common-misc.h"
#include "cvm-common-fpa.h"

#include "cvm-enet.h"
#include "cvm-enet-config.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"

#include "cvm-tcp.h"
#include "cvm-tcp-fast.h"
#include "cvm-tcp-init.h"

#include "cvm-udp.h"

#include "inicrmngr.h"

#include "inic.h"


/*
 * prototypes
 */
int inic_rmgr_do_stats(cvm_common_wqe_t* swp, inic_rmngr_request_t* req);
int inic_rmgr_do_fpa(cvm_common_wqe_t* swp, inic_rmngr_request_t* req);
int inic_rmngr_handle_error(cvm_common_wqe_t* swp, inic_rmngr_request_t* req);
int inic_rmngr_send_udp_out(cvm_common_wqe_t* swp, void* resp, int resp_len);
int inic_rmngr_do_tcp_stats(inic_rmngr_request_t* req, oct_inic_resp_tcp_stats_t* tcp_stats_resp);
int inic_rmngr_do_fpa_alloc_count(inic_rmngr_request_t* req, oct_inic_resp_fpa_alloc_t* resp);
int inic_rmngr_do_fpa_current_count(inic_rmngr_request_t* req, oct_inic_resp_fpa_current_t* resp);
uint16_t inic_rmngr_calculate_ip_header_checksum(cvm_ip_ip_t *ip);

int
inic_rmngr_do_ipfrag_commands(cvm_common_wqe_t* swp, inic_rmngr_request_t* req);

/*
 * 
 * Return:
 *
 * int inic_rmngr_process_request(cvm_common_wqe_t *swp)
 *
 * 0 - valid UDP remote request; processed and out the output in out_swp
 * 1 - normal UDP packet; pass it on to the udp stack
 *
 */
int inic_rmngr_process_request(cvm_common_wqe_t *swp)
{
    int retval = 1;
    cvm_ip_ip_t *ip = NULL;
    struct cvm_udp_udphdr *uh = ((struct cvm_udp_udphdr *) &(swp->hw_wqe.packet_data[swp->l4_offset]));
    inic_rmngr_request_t *request = NULL;

    /* bypass any IPv6 traffic */
    if (swp->hw_wqe.word2.s.is_v6)
    {
        return (retval);
    }

    /* verify that the it is a request for remote manager */
    if (uh->uh_dport != INIC_RMNGR_UDP_PORT)
    {
        return (retval);
    }

    /* find out the request type */
    ip = CASTPTR(cvm_ip_ip_t, (swp->hw_wqe.packet_ptr.s.addr + CVM_ENET_ETHER_HDR_LEN) );
    request = CASTPTR(inic_rmngr_request_t,(swp->hw_wqe.packet_ptr.s.addr+CVM_ENET_ETHER_HDR_LEN+sizeof(struct cvm_udp_udphdr)+(ip->ip_hl << 2) ) );

    if (request->signature != INIC_RMNGR_REQ_SIG)
    {
        return (retval);
    }


    switch (request->opcode.major)
    {
        case INIC_RMNGR_MJAOR_GET_STATS:
	{
	    inic_rmgr_do_stats(swp, request); 
	}
	break;

        case INIC_RMNGR_MJAOR_GET_FPA:
        {
	    inic_rmgr_do_fpa(swp, request);
        }
	break;

        case INIC_RMNGR_MJAOR_CSR:
	{

	}
	break;

        case INIC_RMNGR_MJAOR_DBG_LVL:
	{

	}
	break;

	case INIC_RMNGR_MAJOR_IPFRAG:
        {
	    inic_rmngr_do_ipfrag_commands(swp, request);
	}
	break;


        default:
            printf("%s: Invalid opcode for remote request (%d)\n", __FUNCTION__, request->opcode.major);
	    inic_rmngr_handle_error(swp, request); 
	    break;
    }

    retval = 0;
    
    return (retval);
}



/*
 *  inic_rmgr_do_stats()
 */
int inic_rmgr_do_stats(cvm_common_wqe_t* swp, inic_rmngr_request_t* req)
{
    /* check tehe minor op-code */
    switch(req->opcode.minor)
    {
        case INIC_RMNGR_MINOR_TCP:
	{
	    oct_inic_resp_tcp_stats_t resp_tcp_stats;
	    inic_rmngr_do_tcp_stats(req, &resp_tcp_stats);
            inic_rmngr_send_udp_out(swp, &resp_tcp_stats, sizeof(oct_inic_resp_tcp_stats_t) );
	}
	break;

        case INIC_RMNGR_MINOR_EXTRA:
	{

	}
	break;
    }


    return (0);
}


/*
 *  inic_rmgr_do_fpa()
 */
int inic_rmgr_do_fpa(cvm_common_wqe_t* swp, inic_rmngr_request_t* req)
{
    /* check tehe minor op-code */
    switch(req->opcode.minor)
    {
        case INIC_RMNGR_MINOR_ALLOC_COUNT:
	{
	    oct_inic_resp_fpa_alloc_t resp_fpa_alloc_count;
	    inic_rmngr_do_fpa_alloc_count(req, &resp_fpa_alloc_count);
            inic_rmngr_send_udp_out(swp, &resp_fpa_alloc_count, sizeof(oct_inic_resp_fpa_alloc_t) );
	}
	break;

        case INIC_RMNGR_MINOR_CURRENT_COUNT:
	{
	    oct_inic_resp_fpa_current_t resp_fpa_current_count;
	    inic_rmngr_do_fpa_current_count(req, &resp_fpa_current_count);
            inic_rmngr_send_udp_out(swp, &resp_fpa_current_count, sizeof(oct_inic_resp_fpa_current_t) );
	}
	break;
    }


    return (0);
}


/*
 *  inic_rmngr_handle_error()
 */
int inic_rmngr_handle_error(cvm_common_wqe_t* swp, inic_rmngr_request_t* req)
{
    return (0);
}


/*
 *  inic_rmngr_send_udp_out()
 */ 
int inic_rmngr_send_udp_out(cvm_common_wqe_t* swp, void* resp, int resp_len)
{
    char tmp_mac[CVM_ENET_ETHER_ADDR_LEN];
    uint32_t tmp_ipv4_addr;                  /* IPv4 */
    cvm_ip_ip_t *ip = NULL;
    struct cvm_udp_udphdr *uh = NULL;
    uint16_t tmp_udp_port = 0;
    int ihlen = 0x0;
    char* payload_ptr = NULL;

    /* 
     * Note: use the origirnal swp and packet ptr; change the following 
     *       fields in header:
     *
     *       - swap MAC addresses
     *       - swap IPv4 addresses
     *       - set Ipv4 pay load len
     *       - update header checksum
     *
     */

    /* swap MAC addresses */
    memcpy( (void*)tmp_mac, CASTPTR(void, ((uint64_t)swp->hw_wqe.packet_ptr.s.addr) ), CVM_ENET_ETHER_ADDR_LEN);
    memcpy( CASTPTR(void, ((uint64_t)swp->hw_wqe.packet_ptr.s.addr) ), CASTPTR(void, ((uint64_t)(swp->hw_wqe.packet_ptr.s.addr+CVM_ENET_ETHER_ADDR_LEN)) ), CVM_ENET_ETHER_ADDR_LEN );
    memcpy( CASTPTR(void, ((uint64_t)(swp->hw_wqe.packet_ptr.s.addr+CVM_ENET_ETHER_ADDR_LEN)) ), (void*)tmp_mac, CVM_ENET_ETHER_ADDR_LEN);

    /* swap IP addresses */
    ip = CASTPTR(cvm_ip_ip_t,((uint64_t)(swp->hw_wqe.packet_ptr.s.addr + CVM_ENET_ETHER_HDR_LEN)) );
    ihlen = (ip->ip_hl << 2);

    tmp_ipv4_addr = ip->ip_src.s_addr;
    ip->ip_src.s_addr = ip->ip_dst.s_addr;
    ip->ip_dst.s_addr = tmp_ipv4_addr;

    /* set ipv4 payload length correctly */
    ip->ip_len = ihlen + sizeof(struct cvm_udp_udphdr) + resp_len;

    /* setup UDP header correctly */
    uh = CASTPTR(struct cvm_udp_udphdr, ((uint64_t)(swp->hw_wqe.packet_ptr.s.addr + CVM_ENET_ETHER_HDR_LEN + ihlen)) );
    tmp_udp_port = uh->uh_sport;
    uh->uh_sport = uh->uh_dport;
    uh->uh_dport = tmp_udp_port;

    uh->uh_ulen = ip->ip_len - ihlen;
    uh->uh_sum = 0x0;

    /* now calculate IP checksum */
    ip->ip_sum = inic_rmngr_calculate_ip_header_checksum(ip);

    /* copy the response */
    payload_ptr = CASTPTR(char,( CAST64(uh) + (uint64_t)sizeof(struct cvm_udp_udphdr)) );
    memcpy( (void*)payload_ptr, (void*)resp, resp_len);

    /* enqueue the packet */
    swp->opprt = swp->hw_wqe.ipprt;
    swp->control.gth = 0;
    swp->hw_wqe.word2.s.bufs = 1;
    swp->hw_wqe.packet_ptr.s.size = swp->hw_wqe.len = ip->ip_len + CVM_ENET_ETHER_HDR_LEN;

    cvm_common_enqueue_frame(swp);

    return (0);
}




/*
 * IP header checksum calculation
 */
uint16_t inic_rmngr_calculate_ip_header_checksum(cvm_ip_ip_t *ip)
{
    uint64_t sum;
    uint16_t *ptr = (uint16_t*) ip;
    uint8_t *bptr = (uint8_t*) ip;

    sum  = ptr[0];		
    sum += ptr[1];
    sum += ptr[2];
    sum += ptr[3];
    sum += ptr[4];

    /* Skip checksum field */
    sum += ptr[6];
    sum += ptr[7];
    sum += ptr[8];
    sum += ptr[9];

    /* Check for options */
    if (bptr[0] != 0x45) goto slow_cksum_calc;

return_from_slow_cksum_calc:

    sum = (uint16_t) sum + (sum >> 16);
    sum = (uint16_t) sum + (sum >> 16);
    return ((uint16_t) (sum ^ 0xffff));

slow_cksum_calc:
    /* Addes IPv4 options into the checksum (if present) */
    {
        uint64_t len = (bptr[0] & 0xf) - 5;
        ptr = &ptr[len<<1];

        while (len-- > 0) 
        {
	   sum += *ptr++;
	   sum += *ptr++;
        }
    }

    goto return_from_slow_cksum_calc;
}


/*
 *  inic_rmngr_do_tcp_stats()
 */
int inic_rmngr_do_tcp_stats(inic_rmngr_request_t* req, oct_inic_resp_tcp_stats_t* resp)
{
    cvm_tcp_stats_t tcpstats;
    int retval = 0;

    /* prepare the response */
    resp->response.opcode.major = req->opcode.major;
    resp->response.opcode.minor = req->opcode.minor;
    resp->response.request_id = req->request_id;

    /* collect the tcp stats */
    retval = cvm_tcp_usr_get_all_tcpstat(&tcpstats);
    if (retval)
    {
        resp->response.response_code = INIC_RMNGR_STATS_NOT_COLLECTED;
        return (0);
    }

    /* update the response tcp structre */
    resp->tcp_stats.tcps_connattempt = tcpstats.tcps_connattempt;
    resp->tcp_stats.tcps_accepts = tcpstats.tcps_accepts;
    resp->tcp_stats.tcps_connects = tcpstats.tcps_connects;
    resp->tcp_stats.tcps_drops = tcpstats.tcps_drops;
    resp->tcp_stats.tcps_conndrops = tcpstats.tcps_conndrops;
    resp->tcp_stats.tcps_minmssdrops = tcpstats.tcps_minmssdrops;
    resp->tcp_stats.tcps_closed = tcpstats.tcps_closed;
    resp->tcp_stats.tcps_segstimed = tcpstats.tcps_segstimed;
    resp->tcp_stats.tcps_rttupdated = tcpstats.tcps_rttupdated;
    resp->tcp_stats.tcps_delack = tcpstats.tcps_delack;
    resp->tcp_stats.tcps_timeoutdrop = tcpstats.tcps_timeoutdrop;
    resp->tcp_stats.tcps_rexmttimeo = tcpstats.tcps_rexmttimeo;
    resp->tcp_stats.tcps_persisttimeo = tcpstats.tcps_persisttimeo;
    resp->tcp_stats.tcps_keeptimeo = tcpstats.tcps_keeptimeo;
    resp->tcp_stats.tcps_keepprobe = tcpstats.tcps_keepprobe;
    resp->tcp_stats.tcps_keepdrops = tcpstats.tcps_keepdrops;

    resp->tcp_stats.tcps_sndtotal = tcpstats.tcps_sndtotal;
    resp->tcp_stats.tcps_sndpack = tcpstats.tcps_sndpack;
    resp->tcp_stats.tcps_sndbyte = tcpstats.tcps_sndbyte;
    resp->tcp_stats.tcps_sndrexmitpack = tcpstats.tcps_sndrexmitpack;
    resp->tcp_stats.tcps_sndrexmitbyte = tcpstats.tcps_sndrexmitbyte;
    resp->tcp_stats.tcps_sndrexmitbad = tcpstats.tcps_sndrexmitbad;
    resp->tcp_stats.tcps_sndacks = tcpstats.tcps_sndacks;
    resp->tcp_stats.tcps_sndprobe = tcpstats.tcps_sndprobe;
    resp->tcp_stats.tcps_sndurg = tcpstats.tcps_sndurg;
    resp->tcp_stats.tcps_sndwinup = tcpstats.tcps_sndwinup;
    resp->tcp_stats.tcps_sndctrl = tcpstats.tcps_sndctrl;

    resp->tcp_stats.tcps_rcvtotal = tcpstats.tcps_rcvtotal;
    resp->tcp_stats.tcps_rcvpack = tcpstats.tcps_rcvpack;
    resp->tcp_stats.tcps_rcvbyte = tcpstats.tcps_rcvbyte;
    resp->tcp_stats.tcps_rcvbadsum = tcpstats.tcps_rcvbadsum;
    resp->tcp_stats.tcps_rcvbadoff = tcpstats.tcps_rcvbadoff;
    resp->tcp_stats.tcps_rcvmemdrop = tcpstats.tcps_rcvmemdrop;
    resp->tcp_stats.tcps_rcvshort = tcpstats.tcps_rcvshort;
    resp->tcp_stats.tcps_rcvduppack = tcpstats.tcps_rcvduppack;
    resp->tcp_stats.tcps_rcvdupbyte = tcpstats.tcps_rcvdupbyte;
    resp->tcp_stats.tcps_rcvpartduppack = tcpstats.tcps_rcvpartduppack;
    resp->tcp_stats.tcps_rcvpartdupbyte = tcpstats.tcps_rcvpartdupbyte;
    resp->tcp_stats.tcps_rcvoopack = tcpstats.tcps_rcvoopack;
    resp->tcp_stats.tcps_rcvoobyte = tcpstats.tcps_rcvoobyte;
    resp->tcp_stats.tcps_rcvpackafterwin = tcpstats.tcps_rcvpackafterwin;
    resp->tcp_stats.tcps_rcvbyteafterwin = tcpstats.tcps_rcvbyteafterwin;
    resp->tcp_stats.tcps_rcvafterclose = tcpstats.tcps_rcvafterclose;
    resp->tcp_stats.tcps_rcvwinprobe = tcpstats.tcps_rcvwinprobe;
    resp->tcp_stats.tcps_rcvdupack = tcpstats.tcps_rcvdupack;
    resp->tcp_stats.tcps_rcvacktoomuch = tcpstats.tcps_rcvacktoomuch;
    resp->tcp_stats.tcps_rcvackpack = tcpstats.tcps_rcvackpack;
    resp->tcp_stats.tcps_rcvackbyte = tcpstats.tcps_rcvackbyte;
    resp->tcp_stats.tcps_rcvwinupd = tcpstats.tcps_rcvwinupd;
    resp->tcp_stats.tcps_pawsdrop = tcpstats.tcps_pawsdrop;
    resp->tcp_stats.tcps_predack = tcpstats.tcps_predack;
    resp->tcp_stats.tcps_preddat = tcpstats.tcps_preddat;
    resp->tcp_stats.tcps_usedrtt = tcpstats.tcps_usedrtt;
    resp->tcp_stats.tcps_usedrttvar = tcpstats.tcps_usedrttvar;
    resp->tcp_stats.tcps_usedssthresh = tcpstats.tcps_usedssthresh;
    resp->tcp_stats.tcps_persistdrop = tcpstats.tcps_persistdrop;
    resp->tcp_stats.tcps_badsyn = tcpstats.tcps_badsyn;
    resp->tcp_stats.tcps_listendrop = tcpstats.tcps_listendrop;
    resp->tcp_stats.tcps_badrst = tcpstats.tcps_badrst;

    resp->tcp_stats.tcps_sc_added = tcpstats.tcps_sc_added;
    resp->tcp_stats.tcps_sc_retransmitted = tcpstats.tcps_sc_retransmitted;
    resp->tcp_stats.tcps_sc_dupsyn = tcpstats.tcps_sc_dupsyn;
    resp->tcp_stats.tcps_sc_dropped = tcpstats.tcps_sc_dropped;
    resp->tcp_stats.tcps_sc_completed = tcpstats.tcps_sc_completed;
    resp->tcp_stats.tcps_sc_bucketoverflow = tcpstats.tcps_sc_bucketoverflow;
    resp->tcp_stats.tcps_sc_cacheoverflow = tcpstats.tcps_sc_cacheoverflow;
    resp->tcp_stats.tcps_sc_reset = tcpstats.tcps_sc_reset;
    resp->tcp_stats.tcps_sc_stale = tcpstats.tcps_sc_stale;
    resp->tcp_stats.tcps_sc_aborted = tcpstats.tcps_sc_aborted;
    resp->tcp_stats.tcps_sc_badack = tcpstats.tcps_sc_badack;

    resp->tcp_stats.tcps_sack_recovery_episode = tcpstats.tcps_sack_recovery_episode;
    resp->tcp_stats.tcps_sack_rexmits = tcpstats.tcps_sack_rexmits;
    resp->tcp_stats.tcps_sack_rexmit_bytes = tcpstats.tcps_sack_rexmit_bytes;
    resp->tcp_stats.tcps_sack_rcv_blocks = tcpstats.tcps_sack_rcv_blocks;
    resp->tcp_stats.tcps_sack_send_blocks = tcpstats.tcps_sack_send_blocks;


    /* return success */
    resp->response.response_code = INIC_RMNGR_RESP_SUCCESS;

    return (0);
}


/*
 *  inic_rmngr_do_fpa_alloc_count()
 */
int inic_rmngr_do_fpa_alloc_count(inic_rmngr_request_t* req, oct_inic_resp_fpa_alloc_t* resp)
{
    int i = 0;
    int j = 0;

    /* prepare the response */
    resp->response.opcode.major = req->opcode.major;
    resp->response.opcode.minor = req->opcode.minor;
    resp->response.request_id = req->request_id;

    /* fill up the response structure */
    for (i=0; i<MAX_FPA_POOLS; i++)
    {
        resp->fpa_alloc[i].count = cvm_common_fpa_info[i].count;

	for (j=0; j<cvm_common_fpa_info[i].count; j++)
	{
	    resp->fpa_alloc[i].entry[j].start_addr   = cvm_common_fpa_info[i].entry[j].start_addr;
	    resp->fpa_alloc[i].entry[j].end_addr     = cvm_common_fpa_info[i].entry[j].end_addr;
	    resp->fpa_alloc[i].entry[j].element_size = cvm_common_fpa_info[i].entry[j].element_size;
	    resp->fpa_alloc[i].entry[j].info_base    = cvm_common_fpa_info[i].entry[j].info_base;
	}
    }

    /* return success */
    resp->response.response_code = INIC_RMNGR_RESP_SUCCESS;

    return (0);
}



/*
 * inic_rmngr_do_fpa_current_count()
 */
int inic_rmngr_do_fpa_current_count(inic_rmngr_request_t* req, oct_inic_resp_fpa_current_t* resp)
{
    int i = 0;

    /* prepare the response */
    resp->response.opcode.major = req->opcode.major;
    resp->response.opcode.minor = req->opcode.minor;
    resp->response.request_id = req->request_id;

    /* fill up the response structure */
    for (i=0; i<MAX_FPA_POOLS; i++)
    {
        resp->fpa_count[i] = CVM_COMMON_FPA_AVAIL_COUNT(i);
    }

    /* return success */
    resp->response.response_code = INIC_RMNGR_RESP_SUCCESS;

    return (0);
}


int
inic_rmngr_do_ipfrag_commands(cvm_common_wqe_t* swp, inic_rmngr_request_t* req)
{
	printf("Received IPFRAG request\n");
	printf("Request id: %lld\n", CVM_COMMON_UCAST64(req->request_id));
	printf("Command: %d:%d\n", req->opcode.major, req->opcode.minor);
	printf("Arg1: %d\n", req->arg1);
	printf("Arg2: %d\n", req->arg2);

	switch(req->opcode.minor) {
		case INIC_RMNGR_MINOR_SETMTU:
		{
			char    ifname[8];
			int     mtu = (int)req->arg2;

			sprintf(ifname, "em%d", req->arg1);
			printf("RMNGR: Setting MTU to %d for if: %s\n", mtu, ifname);
			cvm_enet_intf_set_mtu(ifname, &mtu);
		}
		break;
		
		default:
			printf("Unknown Minor Opcode\n");
	}

	return 0;
}

