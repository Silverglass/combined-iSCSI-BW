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
#include <assert.h>
#if defined(linux) && !defined(__KERNEL)
#include <malloc.h>
#include <unistd.h>
#endif

#include "global-config.h"
#include "cvmx-config.h"

#include "cvmx.h"
#include "cvmx-sysinfo.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-pip.h"
#include "cvmx-spinlock.h"
#include "cvmx-coremask.h"
#include "cvmx-bootmem.h"
#include "cvmx-helper.h"
#include "cvmx-malloc.h"
#include "cvmx-scratch.h"
#include "cvmx-gmx.h"
#include "cvmx-ebt3000.h"

#include "cvm-common-wqe.h"
#include "cvm-common-defs.h"
#include "cvm-common-misc.h"
#include "cvm-common-fpa.h"

#include "cvm-enet.h"
#include "cvm-enet-arp.h"
#include "cvm-enet-config.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-route.h"
#include "cvm-ip-sockio.h"
#include "cvm-ip-inline.h"
#include "cvm-ip-config.h"
#include "cvm-ip-if-dl.h"

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#include "cvm-ip6-var.h"
#include "cvm-icmp6.h"
#include "cvm-scope6-var.h"
#include "cvm-ip6-inline.h"
#include "cvm-nd6.h"
#endif

#include "cvm-tcp.h"
#include "cvm-tcp-var.h"
#include "cvm-tcp-fast.h"
#include "cvm-tcp-init.h"

#include "cvm-udp.h"
#include "cvm-udp-var.h"

#include "socketvar.h"
#include "cvm-socket.h"
#include "cvm-socket-cb.h"
#include "cvm-socket-raw.h"

#include "inic.h"

#ifdef INET6
extern void cvm_ip6_in6_ifattach __P((cvm_enet_ifnet_t *, cvm_enet_ifnet_t *));
extern void cvm_ip6_in6_ifdetach __P((cvm_enet_ifnet_t *));
#endif



/* Core and Data masks */
extern CVMX_SHARED unsigned int coremask_app;
extern CVMX_SHARED unsigned int coremask_data;

extern int core_id;
extern CVMX_SHARED int highest_core_id;

/* idle counter (per core) */
uint64_t idle_counter = 0;


/* Ip addresses */
CVMX_SHARED cvm_ip_in_addr_t cvm_ip_address[32];
#ifdef INET6
CVMX_SHARED uint64_t cvm_ip6_address[30][2];
#endif

uint64_t cvm_debug_print_interval = 0;

#ifdef DUTY_CYCLE
uint64_t prev_conn_count = 0;

static uint64_t start_cycle = 0;
static uint64_t end_cycle = 0;
static uint64_t process_start_cycle = 0;
static uint64_t process_end_cycle = 0;
static uint64_t process_count = 0;
#endif /* DUTY_CYCLE */

#ifdef CVM_CLI_APP
CVMX_SHARED volatile uint32_t core_idle_cycles[CVMX_MAX_CORES];
#endif

#ifdef REMOTE_MANAGER
int inic_rmngr_process_request(cvm_common_wqe_t *swp);
#endif /*  REMOTE_MANAGER */

#define ANVL_RFC_793_COMPLIANCE


int inic_data_global_init(void)
{
    int i,iface;
    char xname[4];

#if 0
    static uint64_t default_route_created = 0;
#endif

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_data_global_init\n");

    out_swp = NULL;
    out_swp_tail = NULL;

    /*
     * Make sure we are not in NULL_NULL POW state
     * (if we are, we can't output a packet)
     */
    cvmx_pow_work_request_null_rd();

#ifdef WORK_QUEUE_ENTRY_SIZE_128 // {
    assert(sizeof(cvm_common_wqe_t) == 128);
    assert(CVMX_FPA_WQE_POOL_SIZE == 128);
#else
    assert(sizeof(cvm_common_wqe_t) == 256);
    assert(CVMX_FPA_WQE_POOL_SIZE == 256);
#endif // WORK_QUEUE_ENTRY_SIZE_128 }

#ifdef CVM_CLI_APP
    {
        int a = 0;

        for (a=0; a<CVMX_MAX_CORES; a++)
	{
	    core_idle_cycles[a] = ((a*8) + CVM_FAU_REG_CORE_IDLE_CYCLES);
            cvmx_fau_atomic_write64(core_idle_cycles[a], 0x0);
	}
    }
#endif

    if(cvm_enet_init())
    {
        return 1;
    }

    cvm_ip_ip_init();
#ifdef INET6
    cvm_ip6_ip6_init();
#endif

    cvm_tcp_global_init();
    cvm_udp_global_init();
    cvm_raw_global_init();

#ifdef CVM_ENET_VLAN
    cvm_enet_vif_global_init();
#endif

    /* Configure the L2 interface */
    cvm_intf_autoconfig();

    /*for(i = 1; i < 16; i++)
    {
          cvm_ip_address[i] = 0xc0a801ea + 0x100*(i-6);
    }*/
	
	cvm_ip_address[6] = 0xc0a801d3;
  //cvm_ip_address[7] = 0xc0a802d3;
  //cvm_ip_address[8] = 0xc0a803d3;


	//cvm_ip_address[16] = 0xc0a801d3;


 
    for(iface=0;iface<CVM_ENET_NUM_PIFS;iface++)
    {
    	if (!(activeportmask & (1 << iface))) continue;

    	strcpy(xname, "em");
    	xname[2] = '0' + iface/10;
    	xname[3] = '0' + iface%10;
    	xname[4] = 0;

        /* Adding IP address */
        cvm_enet_intf_add_ipaddr(xname, cvm_ip_address[iface], 0xffffff00);

        /* Flush packet from the output queue */
        //cvm_send_packet();

        for(i=1; i < 2; ++i){
            /* function for adding alias IP address */
            // cvm_enet_intf_add_alias_ipaddr(xname, cvm_ip_address[iface]+i);
            /* Flush packet from the output queue */
            //cvm_send_packet();
        }

#ifdef INET6
#ifdef CVM_ENET_TUNNEL
        if(iface != 16) {
#endif
        /* Auto configure link local address */
        cvm_ip6_in6_ifattach(cvm_enet_ifnet_ptr_get(iface),NULL);

        /* Configure other addresses */
        uint32_t mask_high = 0xffffffff;
        uint32_t mask_low = 0xffffffff;
        uint64_t prefixmask = ((uint64_t)(mask_high) << 32) | ((uint64_t)mask_low);
        cvm_enet_intf_add_ip6addr(xname, cvm_ip6_address[iface][0], cvm_ip6_address[iface][1], prefixmask, 0, 0xffffffff, 0xffffffff);
        cvm_send_packet();
#ifdef CVM_ENET_TUNNEL
       }
#endif
#endif
    }

#ifdef INET6
#ifdef CVM_ENET_TUNNEL
    cvm_enet_tunnel_global_init();
    cvm_enet_add_tunnel(16,2,0xc0a83001,0xc0a83064);
    cvm_ip6_add_route_for_tunnel(0x2000000000000000ULL, 0, 0xe000000000000000ULL,0, 16 ,2, 0);
    cvm_ip_tunnel_show();
#endif
#endif


#if 0
    if (!default_route_created) {
       default_route_created = 1;

       // Change gateway address according 
       // to actual network setup

       if(cvm_ip_add_default_route(0xc0a83014))
          printf("default route addition NOT successful\n");
       else
          printf("default route addition successful\n");
    }
#endif

	/* Display interface information */
	cvm_enet_intf_show();
	printf("\n");



    /* initialize the application side socket library */
    cvm_so_stack_socket_global_init();


#ifdef STACK_PERF

#ifdef INET6

#ifdef APP_ECHO_SERVER_TCP_v4_v6
    /* create a v6 listening socket */
    cvm_so_create_listening_socket_tcp6();

    /* create a v4 listening socket */
    cvm_so_create_listening_socket_tcp();

#else /* APP_ECHO_SERVER_TCP_v4_v6 */

    /* create a v6 listening socket */
    cvm_so_create_listening_socket_tcp6();

#endif /* APP_ECHO_SERVER_TCP_v4_v6 */

#else  /* INET6 */

    /* create a v4 listening socket */
    cvm_so_create_listening_socket_tcp();

#endif

    /* create a UDP listening socket */
    cvm_so_create_listening_socket_udp();

#endif /* STACK_PERF */

    return 0;
}

int inic_data_local_init(void)
{
    core_id = 0;

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_data_local_init\n");

    if ( (cvmx_helper_initialize_packet_io_local()) == -1)
    {
        printf("inic_data_local_init : Failed to initialize/setup input ports\n");
        return (-1);
    }

    core_id = cvmx_get_core_num();
    cvmx_wait(core_id * 500);  /* this is only for pass 1 */
    /*cvm_common_rand8_init();*/

    cvm_ip_local_init();
#ifdef INET6
    cvm_ip6_local_init();
#endif
    cvm_tcp_local_init();
    cvm_so_stack_socket_local_init();
    cvm_udp_local_init();
    cvm_raw_local_init();

    return 0;
}

/**
 * Process incoming packets. 
 */
int inic_data_loop(void)
{
    cvm_common_wqe_t *swp = NULL;
    cvm_tcp_in_endpoints_t conn;
    cvm_tcp_tcphdr_t *th = NULL;
    cvm_ip_ip_t *ih = NULL;
    int ret=0;
    cvmx_sysinfo_t *sys_info_ptr = cvmx_sysinfo_get();
    uint64_t cpu_clock_hz = sys_info_ptr->cpu_clock_hz;
    uint64_t tick_cycle = cvmx_get_cycle();
    uint64_t tick_step;
    uint32_t idle_processing_interval_ticks = (CVM_COMMON_IDLE_PROCESSING_INTERVAL)*(1000*1000)/(CVM_COMMON_TICK_LEN_US);
    uint32_t idle_processing_last_ticks = 0;
#ifdef INET6
    struct cvm_ip6_ip6_hdr *ip6 = NULL;
#ifdef CVM_ENET_TUNNEL
    struct cvm_ip6_ip6_hdr *i6h = NULL;
#endif
#endif


#ifdef CVM_CLI_APP
    uint64_t idle_cycle_start_value;
#endif

    /* for the simulator */
    if (cpu_clock_hz == 0)
    {
        cpu_clock_hz = 333000000;
    }

    tick_step = (CVM_COMMON_TICK_LEN_US * cpu_clock_hz) / 1000000;
    cvm_debug_print_interval = cpu_clock_hz;

#ifndef REAL_HW
    /* for the simulator, set the debug interval to be 3M cycles */
    cvm_debug_print_interval = 3000000;
#endif

#ifdef DUTY_CYCLE
    start_cycle = cvmx_get_cycle();
    process_count = 0;
#endif

    if (cvmx_coremask_first_core(coremask_data)) 
    {
        /* Initiate a timer transaction for arp entry timeouts */
        if(cvm_enet_arp_timeout_init() != CVMX_TIM_STATUS_SUCCESS)
        {
            printf("Failed init of cvm_ip_arp_timeout_init\n");
        }
#ifdef INET6
#if 0
        if(cvm_ip6_nd6_timer_init() != CVMX_TIM_STATUS_SUCCESS)
        {
            printf("Failed init of cvm_ip6_nd6_timer_init\n");
        }
        if(cvm_ip6_nd6_slow_timer_init() != CVMX_TIM_STATUS_SUCCESS)
        {
            printf("Failed init of cvm_ip6_nd6_slow_timer_init\n");
        }
#endif
#endif
    }

#if defined(CVM_COMBINED_APP_STACK)
    /* Flush the packets sent by main_global and main_local */
    if (out_swp)
    {
            printf("inic_data_loop:  before  cvm_send_packet ()\n");
            cvm_send_packet ();
            printf("inic_data_loop:  after  cvm_send_packet ()\n");
    }


    uint64_t app_timeout = cvmx_get_cycle ();
#endif

    printf("Start TCP data loop!\n");


    /* start the main loop */
    while (1)
    {


#if defined(CVM_COMBINED_APP_STACK)
            if ((cvmx_get_cycle () - app_timeout) >= 213333)//cvm_so_app_timeout) 
            {
                    //Renjs
                    //printf("before cvm_so_callbacks[CVM_SO_FNPTR_TIMEOUT_HANDLER\n");
                    if (cvm_so_callbacks[CVM_SO_FNPTR_TIMEOUT_HANDLER]) 
                    {
                            (*(int (*) (void))cvm_so_callbacks[CVM_SO_FNPTR_TIMEOUT_HANDLER]) ();

                            if (out_swp)
                            {
                                    cvm_send_packet ();
                            }
                    }
                    app_timeout = cvmx_get_cycle ();
            }
#endif

#ifdef DUTY_CYCLE
            end_cycle = cvmx_get_cycle();

            /* check the wrap around case */
            if (end_cycle < start_cycle) end_cycle += cpu_clock_hz;

            if ((end_cycle - start_cycle) > cvm_debug_print_interval)
            {
                    inic_do_per_second_duty_cycle_processing();
            }
#endif /* DUTY_CYCLE */

            cvmx_pow_work_request_async_nocheck(CVMX_SCR_WORK, 1);

            /* update the ticks variable */
            while (cvmx_get_cycle() - tick_cycle > tick_step)
            {
                    tick_cycle += tick_step;
                    cvm_tcp_ticks++;
                    if (!(cvm_tcp_ticks & 0x1f)) CVM_COMMON_HISTORY_SET_CYCLE();
            }


            /* do common idle processing */
            if ( (cvm_tcp_ticks - idle_processing_last_ticks) > idle_processing_interval_ticks)
            {
                    if (cvmx_coremask_first_core(coremask_data)) 
                    {
                            cvm_common_do_idle_processing();
                    }

                    idle_processing_last_ticks = cvm_tcp_ticks;
            }


#ifdef CVM_CLI_APP
            idle_cycle_start_value = cvmx_get_cycle();
#endif

            /* get work entry */
            swp = (cvm_common_wqe_t *)cvmx_pow_work_response_async(CVMX_SCR_WORK);
            if (swp == NULL)
            {
                    idle_counter++;

                    if(core_id == highest_core_id)
                    {
                            cvm_enet_check_link_status();
                    }

#ifdef CVM_CLI_APP
                    cvmx_fau_atomic_add64(core_idle_cycles[core_id], (cvmx_get_cycle()-idle_cycle_start_value) );
#endif
                    continue;
            }

            CVM_COMMON_EXTRA_STATS_ADD64 (CVM_FAU_REG_WQE_RCVD, 1);

#ifdef WORK_QUEUE_ENTRY_SIZE_128 // {
	CVMX_PREFETCH0(swp);
#else
        /* Prefetch work-queue entry */
	CVMX_PREFETCH0(swp);
	CVMX_PREFETCH128(swp);
#endif // WORK_QUEUE_ENTRY_SIZE_128 }

	out_swp = 0;
	out_swp_tail = 0;


#ifdef DUTY_CYCLE
	/* we are about to start processing the packet - remember the cycle count */
	process_start_cycle = cvmx_get_cycle();
#endif


	/* Short cut the common case */
	if (cvmx_likely(swp->hw_wqe.unused == 0))
	{
	    goto packet_from_the_wire;
	}
 
        /* added another layer to the check as software bit will have multiple uses */
        switch (swp->hw_wqe.unused) 
        {
	    case CVM_COMMON_WQE_TIMER_INTERRUPT: /* interrupt handling for timer */
            {
                INIC_DECLARE_HSOCKET();
                INIC_GET_HSOCKET_FROM_TIMER_WQE(swp, hsocket, cvm_so_app_tag, cvm_so_app_tag_type);
                cvm_tcp_timeout_handler((cvmx_wqe_t *)swp);
		INIC_DO_DNI_EVENTS(hsocket, cvm_so_app_tag, cvm_so_app_tag_type);
            }
	    break;

            case CVM_COMMON_WQE_LONG_TIMER_INTERRUPT: /* interrupt handling for long timer */
            {
                cvm_tcp_long_timeout_handler((cvmx_wqe_t *)swp);
            }
            break;

	    case CVM_COMMON_WQE_APP_TO_TCP: /* packet from application running on the other core */
            {
                cvm_so_msg_handler_tcp((cvmx_wqe_t *)&(swp->hw_wqe));
            }
	    break;

	    case CVM_COMMON_WQE_APP_TO_UDP: /* packet from application running on the other core */
            {
                cvm_so_msg_handler_udp((cvmx_wqe_t *)&(swp->hw_wqe));
            }
	    break;

	    case CVM_COMMON_WQE_ARP_TIMER_INTERRUPT:
	    {
                cvm_enet_arp_timeout_handler((cvmx_wqe_t *)swp);
	    }
	    break;

#ifdef INET6
            case CVM_COMMON_WQE_ND6_LLINFO_TIMER_INTERRUPT:
	    {
                cvm_ip6_nd6_llinfo_timeout_handler((cvmx_wqe_t *)swp);
            }
            break;

            case CVM_COMMON_WQE_ND6_TIMER_INTERRUPT:
	    {
                cvm_ip6_nd6_timeout_handler((cvmx_wqe_t *)swp);
            }
	    break;

            case CVM_COMMON_WQE_ND6_SLOW_TIMER_INTERRUPT:
	    {
                cvm_ip6_nd6_slow_timeout_handler((cvmx_wqe_t *)swp);
            }
	    break;

            case CVM_COMMON_WQE_ND6_DAD_TIMER_INTERRUPT:
	    {
                cvm_ip6_nd6_dad_timeout_handler((cvmx_wqe_t *)swp);
            }
	    break;
#endif

            case CVM_COMMON_WQE_APP_TO_RAW:
            {
                cvm_so_msg_handler_raw((cvmx_wqe_t *)&(swp->hw_wqe));
            }
            break;

	    default: /* Packet from the wire */
            {

packet_from_the_wire:

#if CVM_PKO_DONTFREE
                swp->hw_wqe.packet_ptr.s.i = CVM_PKO_DONTFREE;
#endif

#ifdef SANITY_CHECKS
                /* we have a work queue entry - do input sanity checks */
                ret = cvm_common_input_sanity_and_buffer_count_update(swp);
#endif

	        if (cvmx_unlikely(swp->hw_wqe.word2.s.rcv_error))
	        {
                    goto discard_swp; /* Receive error */
	        }
	  
#ifndef WORK_QUEUE_ENTRY_SIZE_128 // {
	        {
 	            /* Make sure pre-fetch completed */
	            uint64_t dp = *(volatile uint64_t*)&swp->next;
	        }
#endif // WORK_QUEUE_ENTRY_SIZE_128 }

	        {
	           /* Initialize SW portion of the work-queue entry */
	           uint64_t *dptr = (uint64_t*)(&swp->next);
	           dptr[0] = 0;
	           dptr[1] = 0;
	           dptr[2] = 0;
	           dptr[3] = 0;
	        }

          if(cvmx_unlikely(swp->hw_wqe.word2.s.not_IP))
          {
                  CVM_COMMON_EXTRA_STATS_ADD64 (CVM_FAU_REG_NONIP_RECV, 1);

                  //Add by gxy
                  uint8_t * ptr = cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr);
                  int i=0;

                  //printf("\ninicdata.c [%d] recv packet = ", swp->hw_wqe.ipprt);
                  //for(i=0; i<54; i++)
                  //        printf("%X ", ptr[i]);
                  //printf("\n");


#ifdef BOND
                  if(swp->hw_wqe.ipprt == 7 || swp->hw_wqe.ipprt == 8)
                  {

                          printf("dataloop arp ipprt = %d\n", swp->hw_wqe.ipprt);
                          swp->hw_wqe.ipprt = 6;
                          uint8_t * ptr = cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr);
                          ptr[5] = ptr[37] = 6;
                  }
#endif


	            goto enet_input; /* Non-IP (ARP) */
	        }

	        /* Shortcut classification to avoid multiple lookups */
	        if(
#ifndef INET6
                    swp->hw_wqe.word2.s.is_v6 || 
#endif
                    swp->hw_wqe.word2.s.is_bcast 
#ifndef INET6
                    || swp->hw_wqe.word2.s.is_mcast
#endif
	        )
                {
                    goto discard_swp; /* Receive error */
	        }

#ifdef BOND	
          //Add by gxy
          if(swp->hw_wqe.ipprt == 7 || swp->hw_wqe.ipprt == 8)
          {
          
                          //printf("dataloop ip ipprt = %d\n", swp->hw_wqe.ipprt);
                  swp->hw_wqe.ipprt = 6;
                  uint8_t * ptr = cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr);
                  ptr[5] = 6;
          }
#endif



  	        /* Packet is unicast IPv4, without L2 errors */
                /* (All IP exceptions are dropped.  This currently includes
                 *  IPv4 options and IPv6 extension headers.)
                 */
	        if(cvmx_unlikely(swp->hw_wqe.word2.s.IP_exc))
	        {
                    goto discard_swp;
	        }

	        /* Packet is Ipv4 (and no IP exceptions) */
                if (cvmx_unlikely(swp->hw_wqe.word2.s.is_frag || !swp->hw_wqe.word2.s.tcp_or_udp))
	        {
	            goto enet_input;
	        }

#ifdef ANVL_RFC_793_COMPLIANCE
	        /* RFC 793 says that:
	          - We should send a RST out when we get a packet with FIN set 
	            without the ACK bit set in the flags field. 
	          - We should send a RST out when we get a packet with no flag set.
	          Hence, let TCP stack handle these conditions.
	        */
	        if (cvmx_unlikely(swp->hw_wqe.word2.s.L4_error &&
                    (cvmx_pip_l4_err_t)(swp->hw_wqe.word2.s.err_code != CVMX_PIP_TCP_FLG8_ERR) &&
		    (cvmx_pip_l4_err_t)(swp->hw_wqe.word2.s.err_code != CVMX_PIP_TCP_FLG9_ERR)))
#else
	        if (cvmx_unlikely(swp->hw_wqe.word2.s.L4_error))
#endif
	        {
	            cvm_tcp_handle_error(swp);
                    goto discard_swp;
	        }
	  
	        /* Packet is not fragmented, TCP/UDP, no IP exceptions/L4 errors */
	        /* We can try an L4 lookup now, but we need all the information */
	        ih = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));

                if (!swp->hw_wqe.word2.s.is_v6)
		{
	            /* for IPv4, we must subtract CVM_COMMON_PD_ALIGN rom tcp_offset to get the offset in the mbuf */
	            swp->l4_offset = ((uint16_t)(ih->ip_hl) << 2) + CVM_COMMON_PD_ALIGN;
	            swp->l4_prot = ih->ip_p;
		}
#ifdef INET6
		else
                {
                    ip6 = (struct cvm_ip6_ip6_hdr *) &swp->hw_wqe.packet_data[CVM_COMMON_IP6_PD_ALIGN];

                    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, 
                            "%s: %d Packet trace Src: %s/%d Dest: %s/%d prot: %d len: %d\n", 
                            __FUNCTION__, __LINE__, 
                            cvm_ip6_ip6_sprintf (&ip6->ip6_dst), conn.ie_fport, 
                            cvm_ip6_ip6_sprintf (&ip6->ip6_src), conn.ie_lport,
                            swp->l4_prot, swp->hw_wqe.len);
                    /* for IPv4, we must subtract CVM_COMMON_PD_ALIGN rom tcp_offset to get the offset in the mbuf */
                    swp->l4_offset = CVM_IP6_IP6_HDRLEN;
                    swp->l4_prot = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

                }
#endif

	        th = ((cvm_tcp_tcphdr_t *)&(swp->hw_wqe.packet_data[swp->l4_offset]));

		/* check if it is a TCP packet */
	        if (swp->l4_prot == CVM_IP_IPPROTO_TCP)
                {
#ifdef INET6
                  if (!swp->hw_wqe.word2.s.is_v6)
#endif
		  {
                    CVM_TCP_TCP_DUMP ((void*)ih);

	            /* assume IPv4 for now */
	            conn.ie_laddr = ih->ip_dst.s_addr;
	            conn.ie_faddr = ih->ip_src.s_addr;
	            conn.ie_lport = th->th_dport;
	            conn.ie_fport = th->th_sport;

		    /* do a TCP lookup */
	            swp->tcb = cvm_tcp_lookup(swp);
		  }
#ifdef INET6
		  else
		  {
	            /* assume IPv4 for now */
	            memcpy (&conn.ie6_laddr, &ip6->ip6_dst, sizeof (struct cvm_ip6_in6_addr));
	            memcpy (&conn.ie6_faddr, &ip6->ip6_src, sizeof (struct cvm_ip6_in6_addr));
	            conn.ie_lport = th->th_dport;
	            conn.ie_fport = th->th_sport;

		    /* do a TCP lookup */
	            swp->tcb = cvm_tcp6_lookup (swp);

                    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, "%s: %d TCPv6 lookup Src: %s/%d Dest: %s/%d ret_tcb: 0x%llx\n", 
		                        __FUNCTION__, __LINE__, 
			                cvm_ip6_ip6_sprintf ((cvm_ip6_in6_addr_t *) &conn.ie6_faddr), conn.ie_fport, 
			                cvm_ip6_ip6_sprintf ((cvm_ip6_in6_addr_t *) &conn.ie6_laddr), conn.ie_lport, 
					CAST64(swp->tcb));
		  }
#endif // INET6

		    if(cvmx_likely(swp->tcb))
                    {
		        swp->ifa = swp->tcb->ifa;
		        swp->ifidx = swp->tcb->ifidx;
                    }
                }

	        if(swp->l4_prot == CVM_IP_IPPROTO_UDP)
                {
#ifdef  REMOTE_MANAGER
		    if (!(inic_rmngr_process_request(swp)) )
		    {
		        goto input_done;
		    }
#endif /*  REMOTE_MANAGER */

                    if (!swp->hw_wqe.word2.s.is_v6)
		    {

	                /* assume IPv4 for now */
	                conn.ie_laddr = ih->ip_dst.s_addr;
	                conn.ie_faddr = ih->ip_src.s_addr;
	                conn.ie_lport = th->th_dport;
	                conn.ie_fport = th->th_sport;
		    }
#ifdef INET6
		    else
		    {
	                memcpy (&conn.ie6_laddr, &ip6->ip6_dst, sizeof (struct cvm_ip6_in6_addr));
	                memcpy (&conn.ie6_faddr, &ip6->ip6_src, sizeof (struct cvm_ip6_in6_addr));
	                conn.ie_lport = th->th_dport;
	                conn.ie_fport = th->th_sport;
		    }
#endif // INET6
                }

enet_input:

#ifdef CVM_IP_FORWARDING // {
		/*
		 * If forwarding is enabled, do an early look-up for a cached
		 * route in case the packet needs to be forwarded.
		 */
            swp->control.gth = 0;
#ifdef INET6
            if (!swp->hw_wqe.word2.s.is_v6)
#endif
            {
                CVMX_PREFETCH0(cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr));
                CVMX_PREFETCH0(cvm_ip_cache_bucket_lookup((struct cvm_ip_ip *) &swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));
            }
#ifdef INET6
            else 
            {
#ifdef CVM_IP6_FASTPATH

                struct cvm_ip6_ip6_hdr *dest_ip6 = NULL;

                CVMX_PREFETCH0(cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr));

		dest_ip6 = (struct cvm_ip6_ip6_hdr *)&(swp->hw_wqe.packet_data[CVM_COMMON_IP6_PD_ALIGN]);

                CVMX_PREFETCH0 (cvm_ip6_cache_bucket_lookup(&dest_ip6->ip6_dst));
#endif
            }
#endif
#endif // CVM_IP_FORWARDING }

	       CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "enet_input:ifa %p ifidx 0x%llx\n", swp->ifa, CVM_COMMON_UCAST64(swp->ifidx));

		/* adjust the packet pointer size correctly */
                {
                    uint16_t i = 0;
                    cvmx_buf_ptr_t  *pkt_ptr = &(swp->hw_wqe.packet_ptr);

		    do
                    {
		        pkt_ptr->s.size -= 8;

		        pkt_ptr = (cvmx_buf_ptr_t*)(cvmx_phys_to_ptr(pkt_ptr->s.addr - 8));
		        i++;
                    }
		    while ( cvmx_unlikely(i < swp->hw_wqe.word2.s.bufs) );
                }

	        /* L2 input processing */
	        if (cvm_enet_input_fast(swp))
		{
	            goto input_done;
		}

	        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "ip_input\n");

		/*
		 * L3 input processing
		 * (sets l4_offset & l4_prot in SWQ struct )
		 */
#ifdef INET6
                if (!swp->hw_wqe.word2.s.is_v6)
	        {
#endif
                    ret = cvm_ip_input_fast(swp);
#ifdef INET6
#ifdef CVM_ENET_TUNNEL
                    if(ret == CVM_IP_IPPROTO_IPV6)
                        goto continue_ip6_processing;
#endif
#endif
#ifdef INET6
	        }
                else
	        {
#ifdef CVM_ENET_TUNNEL
                if(swp->hw_wqe.ipprt == 16 && swp->hw_wqe.word2.s.is_v6)
                    goto discard_swp;
continue_ip6_processing:
#ifdef CVM_IP6_FASTPATH
                i6h = (struct cvm_ip6_ip6_hdr *) (cvmx_phys_to_ptr(swp->hw_wqe.packet_ptr.s.addr) + swp->hw_wqe.word2.s.ip_offset);
                CVMX_PREFETCH0(cvm_ip6_cache_bucket_lookup(&i6h->ip6_dst));
#endif
#endif
                ret = cvm_ip6_ip6_input(swp);
	        }
#endif

                if (ret == CVM_IP_FRAG_RCVD)
                {
                    goto input_done;
                }
                else if (ret == CVM_IP_REASS_PKT_RCVD)
                {
		    swp->tcb = cvm_tcp_lookup(swp);
                }
                else if (ret) 
	        {
                    goto input_done;
		}


	        /* L4 protocol processing */
	         CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "tcp_input_fast\n");
#ifdef INET6
                 if (swp->hw_wqe.word2.s.is_v6)
                 {
                     ip6 = (struct cvm_ip6_ip6_hdr *) &swp->hw_wqe.packet_data[CVM_COMMON_IP6_PD_ALIGN];
                     CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, 
                             "%s: %d Dest: %s Src: %s L4_offset: %d\n",
                             __FUNCTION__, __LINE__, cvm_ip6_ip6_sprintf (&ip6->ip6_dst),
                             cvm_ip6_ip6_sprintf (&ip6->ip6_src), swp->l4_offset);
                 }
#endif

		 /* TCP protocol */
	        if (swp->l4_prot == CVM_IP_IPPROTO_TCP) 
                {
#ifdef INET6
#ifdef TCP_DUMP
                    if (swp->hw_wqe.word2.s.is_v6)
                        cvm_tcp_tcp6_dump ((void*)ip6);
#endif
#endif

#ifdef CVM_RAW_TCP_SUPPORT
                    if (cvm_raw_tcp_lookup_match(swp) == 1)
                    {
                        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_5, 
                                "%s: cvm_raw_tcp_lookup_match MATCH found\n", __FUNCTION__);

                        goto raw_input;
                    }
#endif

#if defined(CVM_COMBINED_APP_STACK)
	            cvm_so_hsocket_t *hsocket = NULL;
	            cvm_so_app_tag = swp->hw_wqe.tag;
	            cvm_so_app_tag_type = swp->hw_wqe.tag_type;
#ifdef INET6
                    if (swp->hw_wqe.word2.s.is_v6)
		    {
	                /* IPv6 */
		        ip6 = (struct cvm_ip6_ip6_hdr *) &swp->hw_wqe.packet_data[CVM_COMMON_IP6_PD_ALIGN];
	                memcpy (&conn.ie6_laddr, &ip6->ip6_dst, sizeof (struct cvm_ip6_in6_addr));
	                memcpy (&conn.ie6_faddr, &ip6->ip6_src, sizeof (struct cvm_ip6_in6_addr));

                        CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, "%s: %d DNI TCP/IPv6 processing Src: %s/%d Dest: %s/%d \n", 
		                            __FUNCTION__, __LINE__, 
			                    cvm_ip6_ip6_sprintf ((cvm_ip6_in6_addr_t*)&conn.ie6_faddr), conn.ie_fport, 
			                    cvm_ip6_ip6_sprintf ((cvm_ip6_in6_addr_t*)&conn.ie6_laddr), conn.ie_lport);
		    }
		    else
#endif
		    {
	                /* IPv4 */
	                conn.ie_laddr = ih->ip_dst.s_addr;
	                conn.ie_faddr = ih->ip_src.s_addr;
		    }

	            conn.ie_lport = th->th_dport;
	            conn.ie_fport = th->th_sport;

	            cvm_tcp_process_app (swp, conn, &hsocket);
	            if (hsocket != NULL) 
                    {
		        uint32_t events;
		        events = cvm_so_process_app (hsocket);
		        if (events) 
                        {
		            CVMX_SYNCWS;

		            if (out_swp)
			    {
		                cvm_send_packet ();
			    }
 
		            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "releasing connection tag %llx\n", CVM_COMMON_UCAST64(hsocket->tag));
		            cvmx_pow_tag_sw_null ();
		            cvm_so_notify_app (hsocket, events);
		            cvmx_pow_tag_sw_full (NULL, cvm_so_app_tag, cvm_so_app_tag_type, 0);
		            cvmx_pow_tag_sw_wait ();
		        }
	            }

	            goto input_done;

#else /* #if defined(CVM_COMBINED_APP_STACK) */

	            if (swp->tcb && (swp->control.sc == 0))
	            {
#ifdef INET6
                      if (!swp->hw_wqe.word2.s.is_v6)
#endif
	              {	
		        ret = cvm_tcp_input_fast(swp);

		        if (ret != CVM_TCP_ENOTFAST) 
			{
		            goto input_done;
			}
		      }
#ifdef INET6
		      else
		      {
			  ret = CVM_TCP_ENOTFAST;
		      }
#endif
	            }

                    if (!swp->hw_wqe.word2.s.is_v6)
		    {

	                cvm_tcp_tcp_input(swp, &conn);
	                goto input_done;
		    }
#ifdef INET6
		    else
		    {
	                cvm_tcp_tcp6_input(swp, &conn);
	                goto input_done;
		    }
#endif

#endif /* #if defined(CVM_COMBINED_APP_STACK) */

	        } /* if TCP */

	        /* UDP protocol */
	        if (swp->l4_prot == CVM_IP_IPPROTO_UDP)
                {
		    {
		        /* swp l4 offset and protocol may not have been updated yet */
		        cvm_update_l4_offset_prot(swp);
		    }

#if defined(CVM_COMBINED_APP_STACK)
	            cvm_so_hsocket_t *hsocket = NULL;

		    /* these are updated inside cvm_udp_udp_input(); keep the compiler happy */
		    conn.ie_lport = conn.ie_fport = 0;

                    cvm_udp_process_app (swp, conn, &hsocket);

	            if (hsocket != NULL) {
                        uint32_t events;
                        events = cvm_so_process_app (hsocket);
                        if (events) {
                            cvmx_pow_tag_sw_null ();
                            cvm_so_notify_app (hsocket, events);
                            cvmx_pow_tag_sw_full (NULL, cvm_so_app_tag, cvm_so_app_tag_type, 0);
                            cvmx_pow_tag_sw_wait ();
                        }
	            }
	            goto input_done;
#else
	            cvm_udp_udp_input (swp, &conn);
	            goto input_done;
#endif
	        }

                // place holder for IP6 'l4_prot'

		/* ICMP protocol */
                if (swp->l4_prot == CVM_IP_IPPROTO_ICMP) 
                {
                    uint8_t icmp_type;
                    uint8_t icmp_code;

                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "icmp_input\n");

                    ih             = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));
                    swp->l4_offset = ((uint16_t)(ih->ip_hl) << 2) + CVM_COMMON_PD_ALIGN;
                    icmp_type      = swp->hw_wqe.packet_data[swp->l4_offset];
                    icmp_code      = swp->hw_wqe.packet_data[swp->l4_offset + 1];

                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_5,
                            "%s: INPUT: ipproto %d icmp_type %d icmp_code %d, swp 0x%llx wqe_len %d bufs %d s.addr 0x%llx s.size %d\n",
                            __FUNCTION__, swp->l4_prot, icmp_type, icmp_code, CAST64(swp), 
                            swp->hw_wqe.len, swp->hw_wqe.word2.s.bufs,
                            CAST64(swp->hw_wqe.packet_ptr.s.addr), swp->hw_wqe.packet_ptr.s.size);

                    /*
                     * All ICMP messages except 
                     * - Echo request
                     * - Timestamp request 
                     * - Address Mask Request 
                     * are passed onto raw sockets (if "raw sockets" are used)
                     */
                    if ((icmp_type == CVM_IP_ICMP_ECHO)   ||
                        (icmp_type == CVM_IP_ICMP_TSTAMP) ||
                        (icmp_type == CVM_IP_ICMP_MASKREQ)) 
                    {
                        /* Pass the incoming packets to ICMP */
                        cvm_ip_icmp_input(swp);
                        goto input_done;
                    }
                    else
                    {
                        /* 
                         * If "raw sockets" is used:
                         * - (1) make a copy of the incoming packet (including wqe)
                         * - (2) pass the original incoming packet to ICMP
                         * - (3) pass the copy to raw sockets 
                         */

                        /* (1) Make a copy of the incoming packet */
                        cvm_common_wqe_t *swp_tmp = NULL;
                        swp_tmp = (cvm_common_wqe_t *)cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
                        if (swp_tmp == NULL)
                        {
                            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
                                    "%s: swp_tmp 0x%llx (NULL), cmv_so_alloc_buffer alloc FAILED\n",
                                    __FUNCTION__, CAST64(swp_tmp));
                            set_last_error(CVM_COMMON_ENOMEM);
                            cvm_ip_icmp_input(swp);     /* Pass the packet to ICMP */
                            goto input_done;
                        }
                        memcpy(swp_tmp, swp, sizeof(cvm_common_wqe_t));


                        /* buf > 1 : reassembly case */
                        if (swp->hw_wqe.word2.s.bufs > 1)
                        {
                            /* make a copy of the chained list */
                            {
                                int i = 0;
                                cvmx_buf_ptr_t new_ptr;
                                cvmx_buf_ptr_t ptr_to;
                                cvmx_buf_ptr_t ptr_from;

                                bzero(&new_ptr,  sizeof(cvmx_buf_ptr_t));
                                bzero(&ptr_to,   sizeof(cvmx_buf_ptr_t));
                                bzero(&ptr_from, sizeof(cvmx_buf_ptr_t));

                                ptr_from        = swp->hw_wqe.packet_ptr;
                                ptr_from.s.size = swp->hw_wqe.packet_ptr.s.size;
                                i = 0;
                                while (i < swp_tmp->hw_wqe.word2.s.bufs)
                                {
                                    new_ptr = cvm_so_alloc_buffer(ptr_from.s.size);
                                    if (new_ptr.s.addr == 0x0)
                                    {
                                        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
                                                "%s: ptr 0x%llx, cmv_so_alloc_buffer FAILED to allocate %d bytes\n",
                                                __FUNCTION__, CAST64(new_ptr.s.addr), ptr_from.s.size);
                                        set_last_error(CVM_COMMON_ENOMEM);

                                        swp_tmp->hw_wqe.word2.s.bufs = i;
                                        cvm_common_packet_free(swp_tmp);
                                        cvm_common_free_fpa_buffer (swp_tmp, CVMX_FPA_WQE_POOL, CVMX_FPA_WQE_POOL_SIZE/CVMX_CACHE_LINE_SIZE);
                                        swp_tmp = NULL;
                                        cvm_ip_icmp_input(swp);    /* Pass the packet to ICMP */
                                        goto input_done;
                                    }

                                    /* offset s.addr pointer by atleast 8 bytes to leave space at the beginning for next_ptr of the chained list */
                                    new_ptr.s.addr = new_ptr.s.addr + 8;
                                    memcpy(CASTPTR(void, new_ptr.s.addr), CASTPTR(void, ptr_from.s.addr), ptr_from.s.size);
                                    new_ptr.s.size = ptr_from.s.size;
                                    new_ptr.s.i    = ptr_from.s.i;
                                    new_ptr.s.back = ptr_from.s.back;
                                    new_ptr.s.pool = ptr_from.s.pool;

                                    if (i == 0)
                                    {
                                        swp_tmp->hw_wqe.packet_ptr = new_ptr;
                                    }
                                    else
                                    {
                                        *((cvmx_buf_ptr_t *)(cvmx_phys_to_ptr(ptr_to.s.addr - 8))) = new_ptr;
                                    }
                                    ptr_to = new_ptr;
                                    ++i;
                                    if (i < swp_tmp->hw_wqe.word2.s.bufs)
                                        ptr_from = *((cvmx_buf_ptr_t *)(cvmx_phys_to_ptr(ptr_from.s.addr - 8)) );
                                }
                            } /* make a copy of the chained list */

                            CVMX_SYNCWS;
                        }
                        else
                        {
                            /* Make a copy of the packet_ptr */
                            cvmx_buf_ptr_t packet_ptr_tmp;
                            packet_ptr_tmp = cvm_so_alloc_buffer(swp->hw_wqe.packet_ptr.s.size);
                            if (packet_ptr_tmp.s.addr == 0x0)
                            {
                                CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
                                        "%s: packet_ptr_tmp 0x%llx, cmv_so_alloc_buffer FAILED to allocate %d bytes\n",
                                        __FUNCTION__, CAST64(packet_ptr_tmp.s.addr), swp->hw_wqe.packet_ptr.s.size);
                                set_last_error(CVM_COMMON_ENOMEM);
                                cvm_common_free_fpa_buffer (swp_tmp, CVMX_FPA_WQE_POOL, CVMX_FPA_WQE_POOL_SIZE/CVMX_CACHE_LINE_SIZE);
                                swp_tmp = NULL;
                                cvm_ip_icmp_input(swp);   /* Pass the packet to ICMP */
                                goto input_done;
                            }
                            memcpy(CASTPTR(void, packet_ptr_tmp.s.addr), CASTPTR(void, swp->hw_wqe.packet_ptr.s.addr), swp->hw_wqe.packet_ptr.s.size);
                            swp_tmp->hw_wqe.packet_ptr = packet_ptr_tmp;
                        }

                        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_5,
                                "%s: COPY:  ipproto %d icmp_type %d icmp_code %d, swp_tmp 0x%llx wqe_len %d bufs %d s.addr 0x%llx s.size %d\n",
                                __FUNCTION__, swp->l4_prot, icmp_type, icmp_code, CAST64(swp_tmp), 
                                swp_tmp->hw_wqe.len, swp_tmp->hw_wqe.word2.s.bufs,
                                CAST64(swp_tmp->hw_wqe.packet_ptr.s.addr), swp_tmp->hw_wqe.packet_ptr.s.size);


                        /*
                         * (2) Pass the original incoming packet to ICMP 
                         */
                        cvm_ip_icmp_input(swp);


                        /*
                         * (3) Pass the copy to raw sockets 
                         */
#if defined(CVM_COMBINED_APP_STACK)
                        cvm_so_app_tag      = swp->hw_wqe.tag;
                        cvm_so_app_tag_type = swp->hw_wqe.tag_type;

                        cvm_raw_raw_input(swp_tmp);
                        cvm_so_process_app_raw ();
#else
                        cvm_raw_raw_input(swp_tmp);
#endif
                        goto input_done;
                    }
                    /* goto input_done; */
                }

#ifdef INET6
                /* ICMP6 protocol */
                if (swp->l4_prot == CVM_IP_IPPROTO_ICMPV6) 
                {
                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "icmp6_input\n");
                    cvm_ip6_icmp6_input(swp);
                    goto input_done;
                }
#endif


                /* raw input */
#ifdef CVM_RAW_TCP_SUPPORT
raw_input:      
                if (swp->l4_prot != CVM_IP_IPPROTO_UDP)
#else
                if ((swp->l4_prot != CVM_IP_IPPROTO_UDP)  &&
                    (swp->l4_prot != CVM_IP_IPPROTO_TCP))
#endif
                {
#if defined(CVM_COMBINED_APP_STACK) 
                    cvm_so_app_tag      = swp->hw_wqe.tag;
                    cvm_so_app_tag_type = swp->hw_wqe.tag_type;

                    cvm_raw_raw_input(swp);
                    cvm_so_process_app_raw();
                    goto input_done;
#else
                    cvm_raw_raw_input(swp);
                    goto input_done;
#endif
                }

                /* Drop anything else */
	        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "Drop anything else\n");
	        goto discard_swp;

input_done:
            ; /* */

            } /* packet from wire */
        } /* switch */


output:
	CVMX_SYNCWS;

	/* Send packet out */
	if (out_swp)
	{
	    cvm_send_packet();
	}

#ifdef DUTY_CYCLE
	process_end_cycle = cvmx_get_cycle();
	process_count += (process_end_cycle - process_start_cycle);
#endif
    }

    return (0);


discard_swp:
    /* Free the chained buffers */
    cvm_common_packet_free(swp);

    /* Free the work queue entry */
    cvm_common_free_fpa_buffer(swp, CVMX_FPA_WQE_POOL, CVMX_FPA_WQE_POOL_SIZE / CVMX_CACHE_LINE_SIZE);
    swp = NULL;
    goto output;

} /* inic_data_loop */



#ifdef DUTY_CYCLE
inline int inic_do_per_second_duty_cycle_processing()
{
    if ( cvmx_coremask_first_core(coremask_data) )
    {
        CVM_COMMON_SIMPRINTF("cycles: %lld (%lld), idle count=%lld\n", (ll64_t)(end_cycle - start_cycle), (ll64_t)(process_count), (ll64_t)(idle_counter));
    }

    process_count = 0;
    idle_counter = 0;
    start_cycle = cvmx_get_cycle();

    if ( cvmx_coremask_first_core(coremask_data) )
    {
        int i=0;
        uint64_t fpa_hw_counters[8];
#ifndef REAL_HW
	uint64_t fpa_counters[8];

#endif


    for (i=0; i<8; i++)
    {
#ifndef REAL_HW
        fpa_counters[i] = (uint64_t)(CVM_COMMON_GET_FPA_USE_COUNT(i));
#endif
        fpa_hw_counters[i] =  CVM_COMMON_FPA_AVAIL_COUNT(i);
    }



    //CVM_COMMON_SIMPRINTF("Connection count = %lld (%lld)\n",  (ll64_t)(total_conn_count), (ll64_t)(conn_count));
    CVM_COMMON_SIMPRINTF("%6lld : %6lld : %6lld : %6lld\n", (ll64_t)(fpa_hw_counters[0]), (ll64_t)(fpa_hw_counters[1]), (ll64_t)(fpa_hw_counters[2]), (ll64_t)(fpa_hw_counters[3]));
    CVM_COMMON_SIMPRINTF("%6lld : %6lld : %6lld : %6lld\n", (ll64_t)(fpa_hw_counters[4]), (ll64_t)(fpa_hw_counters[5]), (ll64_t)(fpa_hw_counters[6]), (ll64_t)(fpa_hw_counters[7]));

#ifdef TCP_TPS_SIM
    {
        uint64_t total_conn_count = ((uint64_t)(cvmx_fau_fetch_and_add32(CVMX_FAU_REG_TCP_CONNECTION_COUNT, 0)));
        cvmx_fau_atomic_write32(CVMX_FAU_REG_TCP_CONNECTION_COUNT, 0);
        CVM_COMMON_SIMPRINTF("Total TPS count = %lu\n", total_conn_count);
    }
#endif

    }

    return (0);
}
#endif /* DUTY_CYCLES */




#ifdef CVM_CLI_APP

extern int uart_printf(int uart_index, const char *format, ...);
extern inline uint8_t uart_read_byte(int uart_index);


#define uprint(format, ...) uart_printf(0, format, ##__VA_ARGS__)
#define ugetchar() uart_read_byte(0);


/*
 * ANSCII escape sequences
 */
#define CLI_GOTO_TOP    "\033[1;1H"    /* ESC[1;1H begins output at the top of the terminal (line 1) */
#define CLI_ERASE_WIN   "\033[2J"      /* Erase the window */
#define CLI_REVERSE     "\033[7m"      /* Reverse the display */
#define CLI_NORMAL      "\033[0m"      /* Normal display */
#define CLI_CURSOR_ON   "\033[?25h"    /* Turn on cursor */
#define CLI_CURSOR_OFF  "\033[?25l"    /* Turn off cursor */
#define CLI_BOLD        "\033[1m"      /* Bold display */


void inic_top(void)
{
    int i = 0;
    int c = 0;

    static uint64_t last_core_idle_value[CVMX_MAX_CORES];
    uint64_t idle_delta[CVMX_MAX_CORES];
    int first_loop = 1;
    cvmx_sysinfo_t *sys_info_ptr = cvmx_sysinfo_get();

    uprint(CLI_CURSOR_OFF);

    while(c==0x0)
    {
        uprint(CLI_GOTO_TOP);
        uprint(CLI_ERASE_WIN);
        uprint("\n");

        if (first_loop)
	{
	    for (i=0; i<CVMX_MAX_CORES; i++) last_core_idle_value[i] = cvmx_fau_fetch_and_add64(core_idle_cycles[i], 0x0);
	    cvmx_wait(sys_info_ptr->cpu_clock_hz);
	    first_loop = 0;
            c = ugetchar();
	    continue;
	}

	for (i=0; i<CVMX_MAX_CORES; i++)
	{
            idle_delta[i] = cvmx_fau_fetch_and_add64(core_idle_cycles[i], 0x0) - last_core_idle_value[i];
	    last_core_idle_value[i] = cvmx_fau_fetch_and_add64(core_idle_cycles[i], 0x0);

	    if (idle_delta[i] > sys_info_ptr->cpu_clock_hz) idle_delta[i] = sys_info_ptr->cpu_clock_hz;
	}

	uprint(CLI_REVERSE);
	uprint(" Stack Cores Utilization \n");
	uprint(CLI_NORMAL);
	uprint("\n\n");

	for (i=0; i<CVMX_MAX_CORES; i++)
	{
            if ((cvmx_coremask_core(i) & coremask_data) != 0)
	    {
                if (i != cvm_common_get_last_core(coremask_data))
		{
	            float val = (float)((float)idle_delta[i]/(float)sys_info_ptr->cpu_clock_hz);

		    val = (1.0 - val);

	            uprint("    Core %2d : ", i);
		    uprint(CLI_BOLD);
                    uprint("%-3.1f %%\n", ((float)val*100.0));
		    uprint(CLI_NORMAL);
		}
	    }
	}

	uprint("\n\nPress any key to exit...\n");

        cvmx_wait(sys_info_ptr->cpu_clock_hz);
        c = ugetchar();
    }

    uprint(CLI_CURSOR_ON);
}

#endif /*  CVM_CLI_APP */
