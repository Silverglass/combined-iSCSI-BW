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

#ifndef __GLOBAL_CONFIG_H__
#define __GLOBAL_CONFIG_H__
 

/*
 * Various compile time flags
 */

/* Flag to compile the tcp/ip stack for hardware (should be enabled if not running on simulator) */
#define REAL_HW

#define USE_SYNC_ALLOC
#define BOND
/* TCP PCI toe mode flag */
//#define PCI_TOE_MODE
//#define STACK_PERF

/* Various debugging flags */
//#define SANITY_CHECKS
//#define DUTY_CYCLE
//#define FPA_CHECKS
//#define FPA_SANITY_BREAKPOINT

/* Throughput test using IXIA (requires STACK_PERF flag) */
//#define IXIA_THRUPUT_TEST

/* Enables tcp dump like output on the serial console */
//#define TCP_DUMP

/* CLI core flag */
//#define CVM_CLI_APP

/* ANVL RFC793 compliance */
#define ANVL_RFC_COMPLIANCE

/* ANVL Advanced compliance */
#define ANVL_ADV_COMPLIANCE

/* app+stack on all cores (app_input mode) */
#define CVM_COMBINED_APP_STACK

/* Flag to enable tcp STATS */
//#define TCP_STATS

/* Flag to control the WQE size */
#define WORK_QUEUE_ENTRY_SIZE_128

/* Various other flags */
#define CVM_IP_ROUTE_DEBUG
#define CVM_IP_FASTPATH
#define CVM_IP_FORWARDING
#define CVM_IP_REASSEMBLY
#define SC_COUNT_ENABLE
//#define CVM_IP6_PMTU


/* timer enable/disable */

#define TCP_DISABLE_RETRANSMIT_TIMER     0
#define TCP_DISABLE_TIME_WAIT_TIMER      0
#define TCP_DISABLE_KEEPALIVE_TIMER      0
#define TCP_DISABLE_DELAYED_ACK_TIMER    0
#define TCP_DISABLE_PERSIST_TIMER        0
#define TCP_DISABLE_LISTEN_CLOSE_TIMER   0
#define TCP_DISABLE_SYNCACHE_TIMER       0

/* TCP options to be used */
#define TCP_DO_TS_OPT    0     /* Timestamp Option */
#define TCP_DO_SACK_OPT  0     /* Selective ACK option */
#define TCP_DO_WS_OPT    0     /* Window Scaling option */

/* Other TCP settings */
#define TCP_DISABLE_DACK 1     /* disable TCP delayed ACK */


#if TCP_DISABLE_DACK
#define TCP_NO_DACK
#else
#undef TCP_NO_DACK
#endif


/* check various flag dependicies */
#define CVM_PKO_DONTFREE	1      // TCP uses 1 

#ifndef SANITY_CHECKS
#undef FPA_CHECKS
#endif


#ifndef STACK_PERF
#undef IXIA_THRUPUT_TEST
#endif

#ifdef IXIA_THRUPUT_TEST
#define TCP_NO_DACK
#endif


/*
 * iNIC application type to run
 *
 * APP_ECHO_SERVER : run echo server (default)
 * APP_CLIENT      : run client application
 * APP_TCP_ANVL_STUB  : run TCP ANVL Stub application
 * APP_ECHO_SERVER_TCP_v4_v6 : run application listening to both IPv4 and IPv6 addresses
 *
 */
/*#define APP_ECHO_SERVER*/
/*#define APP_CLIENT*/
/*#define APP_TCP_ANVL_STUB*/
/*#define DNI_APP_CLIENT*/
/*#define APP_ECHO_SERVER_TCP_v4_v6*/

/* #define CVM_RAW_IP_LOCAL_PROCESS_ALL */
/* #define APP_SERVER_RAW      */   /* Raw sockets */
/* #define CVM_RAW_TCP_SUPPORT */   /* Raw sockets */
#ifdef CVM_COMBINED_APP_STACK 
/* #define CVM_COMBINED_APP_STACK_ECHO_SERVER_RAW */  /* Raw sockets */
#endif

#ifdef APP_TCP_ANVL_STUB
#undef STACK_PERF
//#define TCP_DUMP
#define SANITY_CHECKS
#define DUTY_CYCLE
#define FPA_CHECKS
#endif

#ifdef USE_ZERO_COPY
#undef STACK_PERF
#endif


#if defined(CVM_COMBINED_APP_STACK)
#undef STACK_PERF
#undef APP_ECHO_SERVER
#undef APP_CLIENT
#endif


#if defined (TCP_TPS_SIM)
#undef REAL_HW
#define STACK_PERF
#define DUTY_CYCLE
#endif

/* Content below this point is only used by the cvmx-config tool, and is
** not used by any C files as CAVIUM_COMPONENT_REQUIREMENT is never
defined.
*/
#ifdef CAVIUM_COMPONENT_REQUIREMENT
 
        /* global resource requirement */
 
        cvmxconfig
        {
                fpa CVM_FPA_128B_POOL
                        size = 1
                        description = "128-byte FPA pool";

                fpa CVM_FPA_256B_POOL
                        size = 2
		        protected = true
                        description = "256-byte FPA pool";

                fpa CVM_FPA_512B_POOL
                        size = 4
                        description = "512-byte FPA pool";

                fpa CVM_FPA_1024B_POOL
                        size = 8
		        protected = true
                        description = "1024-byte FPA pool";

		fau CVM_FAU_PKO_OUTSTANDING
		        size = 8
			description = "total pk0 packets outstanding";

		fau CVM_FAU_PKO_PACKETS
		        size = 8
			description = "total packets sent to pko";

		fau CVM_FAU_PKO_ERRORS
		        size = 8
			description = "total pko errors detected";





#ifdef EXTRA_STATS
                fau CVM_FAU_REG_WQE_RCVD
                        size = 8
                        description = "total number of wqe received";

                fau CVM_FAU_REG_WQE_RCVD_FROM_WIRE
                        size = 8
                        description = "total number of wqe received from wire";

                fau CVM_FAU_REG_NONTCPUDP_SENT
                        size = 8
                        description = "total number of non-tcp/udp sent";

                fau CVM_FAU_REG_NONIP_RECV
                        size = 8
                        description = "total number of non-ip received";

                fau CVM_FAU_REG_PKTS_OUT
                        size = 8
		  description = "total packets out";

#endif


#ifdef CVM_CLI_APP
                fau CVM_FAU_REG_CORE_IDLE_CYCLES
                        size = 8
                        count = 16
		        description = "core idle cycles";
#endif


                scratch CVMX_SCR_WORK
                        size = 8
                        iobdma = true
                        permanent = true
                        description = "Work queue entrys";

	}

#endif

#include "common-config.h"
#include "tcp-config.h"
#include "socket-config.h"

 
#endif  /* __GLOBAL_CONFIG_H__ */








