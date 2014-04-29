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
#if defined(linux) && !defined(__KERNEL__)
#include <malloc.h>
#endif

#include "cvmx-config.h"
#include "executive-config.h"
#include "global-config.h"

#include "cvmx.h"
#include "cvmx-spinlock.h"
#include "cvmx-fpa.h"
#include "cvmx-pip.h"
#include "cvmx-ipd.h"
#include "cvmx-pko.h"
#include "cvmx-dfa.h"
#include "cvmx-pow.h"
#include "cvmx-gmx.h"
#include "cvmx-asx.h"
#include "cvmx-sysinfo.h"
#include "cvmx-coremask.h"
#include "cvmx-malloc.h"
#include "cvmx-bootmem.h"
#include "cvmx-packet.h"
#include "cvmx-helper.h"
#include "cvmx-scratch.h"
#include "cvmx-tim.h"

#include "cvm-common-wqe.h"
#include "cvm-common-defs.h"
#include "cvm-common-misc.h"
#include "cvm-common-fpa.h"
#include "cvm-common-rnd.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-route.h"
#include "cvm-ip-inline.h"



#ifdef INET6
#include "cvm-in6.h"
#include "cvm-ip6.h"
#include "cvm-ip6-var.h"
#endif

#include "socketvar.h"

#include "cvm-tcp.h"
#include "cvm-tcp-var.h"
#include "cvm-tcp-endpt.h"
#include "cvm-tcpiphdr.h"

#include "cvm-udp.h"
#include "cvm-udp-var.h"
#include "cvm-udpip.h"

#include "cvm-socket.h"
#include "cvm-sockmsg.h"

#include "inic.h"

#include "cvm-socket-cb.h"
#include "cvm-socket-raw.h"


#ifdef CVM_CLI_APP
void cli(void);
#endif


/* Shared */
cvmx_arena_list_t CVMX_SHARED main_arenas = NULL;

#ifdef APP_OCTEON_2_OCTEON
CVMX_SHARED char    *g_send_data=NULL; 
CVMX_SHARED char    *g_recv_data=NULL; 
CVMX_SHARED uint32_t g_send_data_size=(10*1024*1024); 
#endif

CVMX_SHARED int num_data_processors = 0;

/* core masks */
CVMX_SHARED unsigned int coremask_app = 0x0;        /* default app core */
CVMX_SHARED unsigned int coremask_data = 0x0;       /* default data core */

extern cvm_ip_in_addr_t cvm_ip_address[];
#ifdef INET6
extern uint64_t cvm_ip6_address[][2];
#endif

/* Core local */
int core_id = -1;

/* Core with the biggest id */
CVMX_SHARED int highest_core_id = -1;


/*
 * Inline funtcions
 */
static inline const char *inic_get_version(void);



/*
 * Return: NULL on failure; otherwire a valid memory address
 */
static void* inic_setup_fpa(int pool, int entry_size, int buf_count, char* pool_name)
{
    void* memory = NULL;
    void* base = NULL;

    memory = cvmx_bootmem_alloc(entry_size * buf_count, entry_size);
    if (memory == NULL)
    {
        printf("%s: Out of memory initializing fpa %s pool...\n", __FUNCTION__, pool_name);
        return (NULL);
    }

    base = CVM_COMMON_INIT_FPA_CHECKS(memory, buf_count, entry_size);
    cvmx_fpa_setup_pool(pool, pool_name, memory, entry_size, buf_count);
    cvm_common_fpa_add_pool_info(pool, memory, entry_size, buf_count, CAST64(base)); 

    return (memory);
}


/*
 * Allocate the memory
 */
static int inic_setup_free_mem(void)
{
    int i = 0;
    cvmx_sysinfo_t *sys_info_ptr = cvmx_sysinfo_get();
    uint64_t sys_mem = sys_info_ptr->system_dram_size;
    int fpa_packet_pool_count = 0;
    int fpa_wqe_pool_count = 0;
    int fpa_output_pool_count = 0;
    int fpa_timer_pool_count = 0;
    int fpa_128b_pool_count = 0;
    int fpa_256b_pool_count = 0;
    int fpa_512b_pool_count = 0;
    int fpa_1024b_pool_count = 0;

    int fpa_ip_128b_pool_count = 0;
    int fpa_ip_256b_pool_count = 0;

    /* check if the sys_mem is returning Mbytes, not the bytes */
    if (sys_mem <= 16*1024)
    {
        /* convert Mbytes to bytes */
        sys_mem = sys_mem * 1024ull * 1024ull;
    }

    sys_mem = 1024ull * 1024ull * 1024ull * 4;

    switch (sys_mem)
    {
    case 256 * 1024 * 1024:
      fpa_packet_pool_count = 8000 + 128; /* max input packets + # recv queues */
      fpa_wqe_pool_count = 8000;
      fpa_output_pool_count = 256;
      fpa_timer_pool_count = 256;
      fpa_128b_pool_count = 8 * 1024;
      fpa_256b_pool_count = 8 * 1024;
      fpa_512b_pool_count = 8 * 1024;      /* number of routes + zero copy usage */
      fpa_1024b_pool_count = 8 * 1024;     /* tcpcbs */
      fpa_ip_128b_pool_count = 512;
      fpa_ip_256b_pool_count = 512;
      break;

    case 512 * 1024 * 1024:
      fpa_packet_pool_count = 20000 + 512; /* max input packets + # recv queues */
      fpa_wqe_pool_count = 20000;
      fpa_output_pool_count = 512;
      fpa_timer_pool_count = 512;
      fpa_128b_pool_count = 64*1024;
      fpa_256b_pool_count = 64*1024;
      fpa_512b_pool_count = 20*1024;       /* number of routes + zero copy usage */
      fpa_1024b_pool_count = 64*1024;      /* tcpcbs */
      fpa_ip_128b_pool_count = 512;
      fpa_ip_256b_pool_count = 512;
      break;

    case 1024ull * 1024ull * 1024ull:
      fpa_packet_pool_count = 40000 + 1024; /* max input packets + # recv queues */
      fpa_wqe_pool_count = 40000;
      fpa_output_pool_count = 1024;
      fpa_timer_pool_count = 65536;;
      fpa_128b_pool_count = 4*65*1024;
      fpa_256b_pool_count = 1*65*1024;
      fpa_512b_pool_count = 80*1024;       /* number of routes + zero copy usage */
      fpa_1024b_pool_count = 4*65*1024;    /* tcpcbs */
      fpa_ip_128b_pool_count = 512;
      fpa_ip_256b_pool_count = 512;
      break;

    case 2048ull * 1024ull * 1024ull:
      fpa_packet_pool_count = 80000 + 1024; /* max input packets + # recv queues */
      fpa_wqe_pool_count = 80000;
      fpa_output_pool_count = 1024;
      fpa_timer_pool_count = 65536*2;
      fpa_128b_pool_count = 4*170*1024;
      fpa_256b_pool_count = 4*170*1024;
      fpa_512b_pool_count = 128*1024;     /* number of routes + zero copy usage */
      fpa_1024b_pool_count = 4*170*1024;  /* tcpcbs */
      fpa_ip_128b_pool_count = 1024;
      fpa_ip_256b_pool_count = 1024;
      break;

    case 4096ull * 1024ull * 1024ull:
      fpa_packet_pool_count = 160000 + 1024; /* max input packets + # recv queues */
      fpa_wqe_pool_count = 160000;
      fpa_output_pool_count = 2048;
      fpa_timer_pool_count = 65536*4;
      fpa_128b_pool_count = 8*170*1024;
      fpa_256b_pool_count = 8*170*1024;
      fpa_512b_pool_count = 2*128*1024;     /* number of routes + zero copy usage */
      fpa_1024b_pool_count = 8*170*1024;  /* tcpcbs */
      fpa_ip_128b_pool_count = 2048;
      fpa_ip_256b_pool_count = 2048;
      break;

    default:
      printf("%s: system memory does not match (sys_mem=%lld)\n", __FUNCTION__, CAST64(sys_mem));
      return (1);
    }

    /*
     * Enable FPA unit
     */
    cvmx_fpa_enable();


    /* populate all the FPA pools */ 
    if ( (inic_setup_fpa(CVM_FPA_1024B_POOL,          CVM_FPA_1024B_POOL_SIZE,          fpa_1024b_pool_count,   "1024B")) == NULL)               return (1);
    if ( (inic_setup_fpa(CVMX_FPA_PACKET_POOL,        CVMX_FPA_PACKET_POOL_SIZE,        fpa_packet_pool_count,  "Packet Buffers")) == NULL)      return (1);
    if ( (inic_setup_fpa(CVMX_FPA_WQE_POOL,           CVMX_FPA_WQE_POOL_SIZE,           fpa_wqe_pool_count,     "Work Queue Entries")) == NULL)  return (1);
    if ( (inic_setup_fpa(CVMX_FPA_OUTPUT_BUFFER_POOL, CVMX_FPA_OUTPUT_BUFFER_POOL_SIZE, fpa_output_pool_count,  "PKO Command Buffers")) == NULL) return (1);
    if ( (inic_setup_fpa(CVMX_FPA_TIMER_POOL,         CVMX_FPA_TIMER_POOL_SIZE,         fpa_timer_pool_count,   "TIM Command Buffers")) == NULL) return (1);
    if ( (inic_setup_fpa(CVM_FPA_128B_POOL,           CVM_FPA_128B_POOL_SIZE,           fpa_128b_pool_count,    "128B")) == NULL)                return (1);
    if ( (inic_setup_fpa(CVM_FPA_256B_POOL,           CVM_FPA_256B_POOL_SIZE,           fpa_256b_pool_count,    "256B")) == NULL)                return (1);
    if ( (inic_setup_fpa(CVM_FPA_512B_POOL,           CVM_FPA_512B_POOL_SIZE,           fpa_512b_pool_count,    "5126B")) == NULL)               return (1);
    if ( (inic_setup_fpa(CVM_IP_128B_POOL,            CVM_IP_128B_POOL_SIZE,            fpa_ip_128b_pool_count, "IP_1286B")) == NULL)            return (1);
    if ( (inic_setup_fpa(CVM_IP_256B_POOL,            CVM_IP_256B_POOL_SIZE,            fpa_ip_256b_pool_count, "IP_256B")) == NULL)             return (1);




    /* setup memory for 5-tuple lookup */
    cvm_tcp_lookup_hash_table_base = cvmx_bootmem_alloc(CVM_TCP_NUM_LOOKUP_BUCKETS * sizeof(cvm_tcp_lookup_block_t), CVMX_CACHE_LINE_SIZE);
    if (cvm_tcp_lookup_hash_table_base == NULL)
    {
        printf("Out of memory initializing lookup_hash_table.\n");       
        return (1);
    }
    memset(cvm_tcp_lookup_hash_table_base, 0, CVM_TCP_NUM_LOOKUP_BUCKETS * sizeof(cvm_tcp_lookup_block_t));


    /* setup memory for 2-tuple lookup */
    cvm_tcp_conn_lookup_hash_table_base = cvmx_bootmem_alloc(CVM_TCP_CONN_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_tcp_lookup_block_t), CVMX_CACHE_LINE_SIZE);
    if (cvm_tcp_conn_lookup_hash_table_base == NULL)
    {
        printf("Out of memory initializing conn_lookup_hash_table.\n");       
        return (1);
    }
    memset(cvm_tcp_conn_lookup_hash_table_base, 0, CVM_TCP_CONN_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_tcp_lookup_block_t));


    /* init spinlocks */
    for (i=0; i<CVM_TCP_CONN_LOOKUP_HASH_TABLE_ENTRIES; i++)
      {
	cvmx_spinlock_init((cvmx_spinlock_t *)(&(((cvm_tcp_lookup_block_t *)cvm_tcp_conn_lookup_hash_table_base)[i].entry[0])));
      }


    /* setup memory for listen socket lookup */
    cvm_tcp_listen_lookup_hash_table_base = cvmx_bootmem_alloc(CVM_TCP_LISTEN_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_tcp_listen_lookup_bucket_t),
                                                   CVMX_CACHE_LINE_SIZE);
    if (cvm_tcp_listen_lookup_hash_table_base == NULL)
    {
        printf("Out of memory initializing listen_lookup_hash_table.\n");       
        return (1);
    }
    memset(cvm_tcp_listen_lookup_hash_table_base, 0, CVM_TCP_LISTEN_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_tcp_listen_lookup_bucket_t));


    /* init spinlocks */
    for (i=0; i<CVM_TCP_LISTEN_LOOKUP_HASH_TABLE_ENTRIES; i++)
      {
	cvmx_spinlock_init(&(((cvm_tcp_listen_lookup_bucket_t *)cvm_tcp_listen_lookup_hash_table_base)[i].listen_lookup_bucket_lock));
      }

    /* setup memory for udp listen socket lookup */
    cvm_udp_g_listen_lookup_hash_table_base = cvmx_bootmem_alloc(CVM_UDP_LISTEN_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_udp_listen_lookup_bucket_t), CVMX_CACHE_LINE_SIZE);
    if (cvm_udp_g_listen_lookup_hash_table_base == NULL)
    {
        printf("Out of memory initializing g_udp_listen_lookup_hash_table.\n");       
        return (1);
    }
    memset(cvm_udp_g_listen_lookup_hash_table_base, 0, CVM_UDP_LISTEN_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_udp_listen_lookup_bucket_t));


    /* init spinlocks */
    for (i=0; i<CVM_UDP_LISTEN_LOOKUP_HASH_TABLE_ENTRIES; i++)
    {
	cvmx_spinlock_init(&(((cvm_udp_listen_lookup_bucket_t *)cvm_udp_g_listen_lookup_hash_table_base)[i].listen_lookup_bucket_lock));
    }

    /* setup memory for listen socket lookup */
    cvm_tcp_port_ref_cnt = (uint32_t *)cvmx_bootmem_alloc(65536 * sizeof(uint32_t), CVMX_CACHE_LINE_SIZE);
    if (cvm_tcp_port_ref_cnt == NULL)
    {
        printf("Out of memory initializing port_ref_cnt.\n");       
        return (1);
    }


    memset(cvm_tcp_port_ref_cnt, 0, 65536 * sizeof(uint32_t));


#ifdef CVM_RAW_TCP_SUPPORT
    /* setup memory for raw socket lookup - for tcp packets ONLY */
    cvm_raw_tcp_g_lookup_hash_table_base = cvmx_bootmem_alloc(CVM_RAW_TCP_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_raw_tcp_lookup_bucket_t), CVMX_CACHE_LINE_SIZE);
    if (cvm_raw_tcp_g_lookup_hash_table_base == NULL)
    {
        printf("%s: Out of memory initializing g_raw_tcp_lookup_hash_table\n", __FUNCTION__);
        return (1);
    }
    memset(cvm_raw_tcp_g_lookup_hash_table_base, 0, CVM_RAW_TCP_LOOKUP_HASH_TABLE_ENTRIES * sizeof(cvm_raw_tcp_lookup_bucket_t));
#endif


#ifdef APP_OCTEON_2_OCTEON
    g_send_data = cvmx_bootmem_alloc(g_send_data_size, CVMX_CACHE_LINE_SIZE);
    if (g_send_data == NULL)
    {
        printf("Out of memory initializing g_send_data %d bytes\n", g_send_data_size);       
        return (1);
    }

    uint32_t _i;
    /* populate send buffer with some pattern */
    for (_i=0; _i<g_send_data_size; _i++)
    {
        g_send_data [_i] = _i%16;
    }

    g_recv_data = cvmx_bootmem_alloc(g_send_data_size, CVMX_CACHE_LINE_SIZE);
    if (g_recv_data == NULL)
    {
        printf("Out of memory initializing g_recv_data %d bytes\n", g_send_data_size);       
        return (1);
    }
    memset(g_recv_data, 0, g_send_data_size);
#endif

   return (0);
}


/* Configure ports */
int inic_setup_input_ports()
{
    int port;
    int num_ports = 32;
    cvmx_pip_port_tag_cfg_t tag_config;
    cvmx_pip_port_cfg_t     port_config;

    if ( (cvmx_helper_initialize_packet_io_global()) == -1)
    {
        printf("%s: Failed to initialize/setup input ports\n", __FUNCTION__);
        return (-1);
    }

    for (port = 0; port < num_ports; port++)
    {

        port_config.u64 = 0;
        port_config.s.qos = port & 7;       /* Have each port go to a different POW queue */
        port_config.s.mode = CVMX_PIP_PORT_CFG_MODE_SKIPL2; /* Process the headers and place the IP header in the work queue */

        /* setup the ports again for ATOMIC tag */
        tag_config.u64 = 0;
        tag_config.s.inc_prt_flag = 0;

        tag_config.s.tcp6_tag_type = CVMX_POW_TAG_TYPE_ATOMIC; /* Keep the order of each port */
        tag_config.s.tcp4_tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
        tag_config.s.ip6_tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
        tag_config.s.ip4_tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
        tag_config.s.non_tag_type = CVMX_POW_TAG_TYPE_ATOMIC;

        tag_config.s.grp = 0;           /* Put all packets in group 0. Other groups can be used by the app */
        tag_config.s.inc_prt_flag  = FALSE;
        tag_config.s.ip6_dprt_flag = TRUE;
        tag_config.s.ip4_dprt_flag = TRUE;
        tag_config.s.ip6_sprt_flag = TRUE;
        tag_config.s.ip4_sprt_flag = TRUE;
        tag_config.s.ip4_pctl_flag = FALSE;
        tag_config.s.ip6_nxth_flag = FALSE;
        tag_config.s.ip6_dst_flag  = TRUE;
        tag_config.s.ip4_dst_flag  = TRUE;
        tag_config.s.ip6_src_flag  = TRUE;
        tag_config.s.ip4_src_flag  = TRUE;

         /* Finally do the actual setup */
         cvmx_pip_config_port(port, port_config, tag_config);
    } /* for */


#ifndef REAL_HW
    {
        int interface;
        for (interface = 0; interface < 2; interface++)
        {
            cvmx_gmxx_inf_mode_t mode;
            mode.u64 = cvmx_read_csr(CVMX_GMXX_INF_MODE(interface));
            if (mode.s.en && mode.s.type)
            {
                uint64_t val = cvmx_read_csr(CVMX_PKO_REG_CRC_ENABLE);
                cvmx_write_csr(CVMX_PKO_REG_CRC_ENABLE, val | (interface ? 0xffff0000ull : 0xffffull));
                cvmx_write_csr(CVMX_GMXX_TX_PRTS(interface), 12);
            }
        }
    }



#endif

    /*
     * Configure RED (Random Early Discard)
     */
    cvmx_helper_setup_red(2000, 1000);

    /* enable IPD */

#if (TEMP_SDK_BUILD_NUMBER > 137)      /* after SDK 1.3.1, this changed */
    cvmx_helper_ipd_and_packet_input_enable();
#else
    cvmx_ipd_enable();
#endif

    return (0);
}

/**
 * Setup the Cavium Simple Executive Libraries using defaults
 * 
 * @return Zero on success
 */
static int inic_init(void)
{
    int i;
    uint8_t *memptr;
    int malloc_arena_size = 8*1024*1024;

    if (inic_setup_free_mem())
    {
        printf("error allocating memory\n");
        return (-1);
    }


    /* Initialize the shared memory allocator with the remaining memory */
    int arena_size = malloc_arena_size;
    int num_arenas = 4;

    for(i=0;i<num_arenas;i++)
    {
        memptr = cvmx_bootmem_alloc(arena_size, malloc_arena_size);


        if (!memptr || cvmx_add_arena(&main_arenas, memptr, arena_size) <0)
        {
            printf("error adding arena: %d!\n", i);
            return (-1);
        }
    }

    CVMX_SYNCWS;

    /* init common here */
    if ( (cvm_common_global_init()) )
    {
        printf("common global init failed\n");
        return (-1);
    }
   
    /*setup_output_queue_tables();*/
    inic_setup_input_ports();    
    CVMX_SYNCWS;


    cvmx_tim_setup(CVM_COMMON_TICK_LEN_US, CVM_COMMON_WHEEL_LEN_TICKS);

    CVMX_SYNCWS;

    /* set get work timeout to 1024-2048 cycles */
    cvmx_write_csr(CVMX_POW_NW_TIM, 0x0);     
    
    /* initialize hardware random unit */
    cvm_common_hw_rand_init();

    return (0);
}

/*
static int cvmx_shutdown(void)
{
    //cvmx_ipd_disable();
    cvmx_pko_disable();
    return 0;
}

static int cvm_inic_shutdown(void)
{
    return cvmx_shutdown();
}
*/

void inic_display_version_info(void)
{
    printf("\n");
    printf("Cavium TCP/IP code compiled on %s %s\n", __DATE__, __TIME__);

#ifdef SDK_VERSION
    printf("%s\n", SDK_VERSION);
#endif

#ifdef GCC_VERSION
    printf("%s\n", GCC_VERSION);
#endif

    printf("\n");
    printf("          Application version : %s\n", inic_get_version());
    printf("          Ethernet version    : %s\n", cvm_enet_get_version());
    printf("          IP version          : %s\n", cvm_ip_get_version());
#ifdef INET6
    printf("          IP6 version         : %s\n", cvm_ip6_get_version());
#endif
    printf("          TCP version         : %s\n", cvm_tcp_get_version());
    printf("          UDP version         : %s\n", cvm_udp_get_version());
    printf("          Socket version      : %s\n", cvm_socket_get_version());
    printf("          Common version      : %s\n", cvm_common_get_version());
    printf("\n");
}

void inic_display_used_flags(void)
{
  printf("\n");
  printf("Compile flags/configuration used:\n");

  printf("\t\tOcteon is pass %d\n", (cvmx_octeon_is_pass1() ? 1 : 2) );

#ifdef REAL_HW
  printf("\t\tREAL_HW\n");
#endif

#ifdef STACK_PERF
  printf("\t\tSTACK_PERF\n");
#endif

#ifdef SANITY_CHECKS
  printf("\t\tSANITY_CHECKS\n");
#endif

#ifdef FPA_CHECKS
  printf("\t\tFPA_CHECKS\n");
#endif

#ifdef DUTY_CYCLE
  printf("\t\tDUTY_CYCLE\n");
#endif

#ifdef IXIA_THRUPUT_TEST
  printf("\t\tIXIA_THRUPUT_TEST\n");
#endif

#ifdef CVM_COMBINED_APP_STACK
  printf("\t\tCVM_COMBINED_APP_STACK\n");
#endif

#ifdef TCP_STATS
  printf("\t\tTCP_STATS\n");
#endif


#ifdef CVMX_ABI_N32
  printf("\t\tCode compiled for N32\n");
#endif

#ifdef INET6
  printf("\t\tIPv6 supported\n");
#endif

#ifdef CVM_ENET_VLAN
  printf("\t\tVLAN supported\n");
#endif

#ifdef CVM_ENET_TUNNEL
  printf("\t\tIPv6-over-IPv4 tunnel supported\n");
#endif

  printf("\n");
}


#define INIC_CORE_COUNT(mask) \
({ \
    int count = 0; \
    int i = 0; \
    unsigned int mask_copy = mask; \
    for (i=0; i<32; i++) { \
        if (mask_copy & 0x1) count++; \
        mask_copy >>= 1; \
    } \
    count;\
})

#define CVM_IP_NETMASK(ip) ((CVM_IP_IN_CLASSA((ip))) ?  \
	CVM_IP_IN_CLASSA_NET : (CVM_IP_IN_CLASSB((ip))) ? CVM_IP_IN_CLASSB_NET : CVM_IP_IN_CLASSC_NET)

void inic_process_cmd_line_args(int argc, char *argv[]) 
{
   int i;
   unsigned int temp[4];
   uint32_t port;
#ifdef INET6
   uint32_t temp6[8];
   uint32_t high[] = {0x22334455, 0x66778899};
   uint32_t low[] = {0x12345678, 0xabcdef32};
#endif

   for (i=0;i<10;i++) { 
       cvm_ip_address[i] = 0xc0a82001 + (i << 8);
#ifdef INET6
       cvm_ip6_address[i][0] = (((uint64_t)(high[0]) << 32) | (uint64_t)(high[1])) + i;
       cvm_ip6_address[i][1] = (((uint64_t)(low[0]) << 32) | (uint64_t)(low[1]));
#endif
   }

#if defined(APP_CLIENT) && defined(APP_OCTEON_2_OCTEON)
   for (i=16;i<20;i++) { 
      cvm_ip_address[i] = 0xc0a82002 + (i << 8);
#ifdef INET6
      cvm_ip6_address[i][0] = (((uint64_t)(high[0]) << 32) | (uint64_t)(high[1])) + i;
      cvm_ip6_address[i][1] = (((uint64_t)(low[0]) << 32) | (uint64_t)(low[1])) + i;
#endif
   }
#else
   for (i=16;i<20;i++) {
      cvm_ip_address[i] = 0xc0a82001 + (i << 8);
#ifdef INET6
      cvm_ip6_address[i][0] = (((uint64_t)(high[0]) << 32) | (uint64_t)(high[1])) + i;
      cvm_ip6_address[i][1] = (((uint64_t)(low[0]) << 32) | (uint64_t)(low[1]));
#endif
   }
#endif

   for (i=0;i<argc;i++) {
      if (!(strncmp(argv[i], "-p", 2))) {
	 sscanf(argv[i], "-p%d=%d.%d.%d.%d", (unsigned int *)&port, &temp[0], &temp[1], &temp[2], &temp[3]);

	 cvm_ip_address[port] = (((temp[0] & 0xff) << 24) | 
	       ((temp[1] & 0xff) << 16) | 
	       ((temp[2] & 0xff) << 8) |
	       (temp[3] & 0xff));
      }
#ifdef INET6
      if (!(strncmp(argv[i], "-6p", 3))) {
          sscanf(argv[i], "-6p%u=%x:%x:%x:%x:%x:%x:%x:%x", (unsigned int *)&port, (unsigned int *)&temp6[0], (unsigned int *)&temp6[1], (unsigned int *)&temp6[2], (unsigned int *)&temp6[3], (unsigned int *)&temp6[4], (unsigned int *)&temp6[5], (unsigned int *)&temp6[6], (unsigned int *)&temp6[7]);

          cvm_ip6_address[port][0] = ((((uint64_t)temp6[0] & 0xffff) << 48) | 
                  (((uint64_t)temp6[1] & 0xffff) << 32) | 
                  (((uint64_t)temp6[2] & 0xffff) << 16) |
                  (temp6[3] & 0xffff));

          cvm_ip6_address[port][1] = ((((uint64_t)temp6[4] & 0xffff) << 48) | 
                  (((uint64_t)temp6[5] & 0xffff) << 32) | 
                  (((uint64_t)temp6[6] & 0xffff) << 16) |
                  (temp6[7] & 0xffff));
      }
#endif
   }

}


/**
 * Main entry point
 * 
 * @return exit code
 */
int main(int argc, char *argv[])
{
   cvmx_sysinfo_t *appinfo = NULL;
    unsigned int coremask_all = 0x0;
    unsigned int coremask_boot = 0x01;                         /* default boot core */
    int result = 0, mask_core_count = 0, total_core_count = 0;
    int num_app_processors = 0;
    int current_active_core_id = 0;
    int current_core_mask = 0;
    int current_core_count = 0;

    cvmx_user_app_init();

    core_id = cvmx_get_core_num();

    /* compute coremask_all on all cores for the first barrier sync below */
    appinfo = cvmx_sysinfo_get();
    coremask_all = appinfo->core_mask;

    /*
     * elect a core to perform boot initializations, as only one core needs to
     * perform this function.  we pick core 0 as that should always be available
     */
#define  COREMASK_BOOT  cvmx_coremask_core(0)  /* core 0 to perform boot init */

    coremask_boot = COREMASK_BOOT;

    /* check if boot core is available */
    if (!(coremask_boot & coremask_all))
    {
        printf("Boot core is not available; unable to initialize (boot core mask = 0x%X)\n", coremask_boot);
        return (result);
    }

    /* coremask_boot performs all the global initializations */
    if (cvmx_coremask_is_member(coremask_boot))
    {
#ifdef SIM
        cvmx_write_csr(CVMX_IPD_SUB_PORT_FCS, 0);
#endif

        /* Get command line arguments */
        //inic_process_cmd_line_args(argc, argv);

	/* take out the POW from null null state (boot core) */
        cvmx_pow_work_request_null_rd();

#if defined(CVM_COMBINED_APP_STACK)
	CVMX_POP (total_core_count, coremask_all);
	num_app_processors = num_data_processors = total_core_count;
	coremask_app = coremask_data = coremask_all;
	printf("\n");
	printf ("No of app processors  : %2d (app coremask  = 0x%x)\n", num_app_processors, coremask_app);
	printf ("No of stack processors: %2d (stack coremask= 0x%x)\n", num_data_processors, coremask_data);
	printf("\n");

	if (cvm_register_dni_callback ()) 
        {
	    printf ("Application callback registration failed (Verify cvm_register_dni_callback ())\n");
	    return (result);
	}

	if (cvm_so_callbacks[CVM_SO_FNPTR_INIT_GLOBAL] && 
	    (*((int (*) ())cvm_so_callbacks[CVM_SO_FNPTR_INIT_GLOBAL])) ()) 
        {
	    printf ("Application init_global callback failed\n");
	    return (result);
	}

	/* Following code is to supress compiler warnings !!!!! */
	mask_core_count = current_active_core_id = current_core_mask = current_core_count = 0;
#else

	/* setup application and data core masks */

#ifdef NUM_APP_PROCESSORS
       num_app_processors = NUM_APP_PROCESSORS;
#endif


#ifdef STACK_PERF
       /* if stack is running in perofrmance mode; setup the core mask correctly */
       num_app_processors = 0x0;
       printf("Stack running in perf mode; core mask = 0x%X\n", coremask_all);
#endif

       num_data_processors = INIC_CORE_COUNT(coremask_all) - num_app_processors;

       /* Check if we have atleast one stack core */
       if (num_data_processors <= 0)
       {
	    printf("Insufficient cores for stack - please verify the coremask\n");
            return (result);
       }

       if ( (num_app_processors + num_data_processors) > CVMX_MAX_CORES)
       {
	    printf("Insufficient cores available - please verify the coremask\n"); 
            return (result);
       }


       coremask_app = coremask_data = 0;
       current_active_core_id = 0;
       current_core_mask = 1;
       current_core_count = 0;

       while(1)
       {
	   if (current_core_count == num_app_processors) break;
           if (coremask_all & current_core_mask)
	   {
	     current_core_count++;
	     coremask_app |= current_core_mask;
	   }

           current_core_mask <<= 1;
       }

       current_core_count = 0;

       while(1)
       {
	   if (current_core_count == num_data_processors) break;
           if (coremask_all & current_core_mask)
	   {
	     current_core_count++;
	     coremask_data |= current_core_mask;
	   }

           current_core_mask <<= 1;
       }


	printf("\n");
	printf ("No of app processors  : %2d (app coremask  = 0x%x)\n", num_app_processors, coremask_app);
	printf ("No of stack processors: %2d (stack coremask= 0x%x)\n", num_data_processors, coremask_data);
	printf("\n");


	/* find the highest data core */
        highest_core_id = cvm_common_get_last_core(coremask_all);

#ifdef CVM_CLI_APP
        highest_core_id = cvm_common_get_last_core(coremask_all & ~(1<<highest_core_id));
#endif

#ifndef STACK_PERF
        if(coremask_all <= 1) /* Need atleast 2 cores for iNIC */
        {
            printf("Insufficient cores (%x).\n", coremask_all);
            return (result);
        }
#endif

	/* check if cores defined in masks are being overlapped */
	if (coremask_app & coremask_data)
	{
            printf("Same core(s) are used for both application and data (app mask = 0x%X, data mask = 0x%X). Exiting\n", 
                   coremask_app, coremask_data);
            return result;
	}

	/* calculate number of cores for app and data */
        total_core_count = INIC_CORE_COUNT(coremask_all);
        mask_core_count =  INIC_CORE_COUNT(coremask_app) + INIC_CORE_COUNT(coremask_data);


#ifndef STACK_PERF
	/* need atleast one data and one application core */
	if ( ( INIC_CORE_COUNT(coremask_app) < 1) || (INIC_CORE_COUNT(coremask_data) < 1 ))
	{
	    printf("Need atleast one application and one data core. (current app core count = %d, current data core count = %d)\n", 
                   INIC_CORE_COUNT(coremask_app), INIC_CORE_COUNT(coremask_data));
            return result;
	}
#endif

        /* verify that enough cores available for both app and data */
        if (mask_core_count > total_core_count)
        {
            printf("Insufficient cores (available = %d, required = %d).\n", total_core_count, mask_core_count);
            return result;
        }

#endif /* CVM_COMBINED_APP_STACK */

        /* Initializations */
        if ((result = inic_init()) != 0)
        {
            printf("Simple Executive initialization failed.\n");
            return (result);
        }

	/* Display version information */
        inic_display_version_info();

	/* Display various FLAGS being defined */
	inic_display_used_flags();

    }
    cvmx_coremask_barrier_sync(coremask_all);

    /* take out the POW from null null state */
    cvmx_pow_work_request_null_rd();

#if defined(CVM_COMBINED_APP_STACK)
    if (cvmx_coremask_is_member (coremask_data)) 
    {
        if (cvm_so_callbacks[CVM_SO_FNPTR_INIT_LOCAL] &&
	    (*((int (*) ())cvm_so_callbacks[CVM_SO_FNPTR_INIT_LOCAL])) ()) 
        {
	    printf ("Application init_local callback failed on core %llu\n", CAST64(cvmx_get_core_num ()));
	    return (result);
        }
    }
    cvmx_coremask_barrier_sync(coremask_all);
#endif

    cvm_common_set_cycle(0);


    cvmx_coremask_barrier_sync(coremask_all);

    /* coremask_boot performs timer start */
    if (cvmx_coremask_is_member(coremask_boot))
    {
        cvmx_tim_start();
    }

    /* Perform core local initializations:
     * (a) common to all
     * (b) based on specific groupings
     */

    /* generic local initializations (both for app and data) */
    inic_generic_local_init();


    if (cvmx_coremask_is_member(coremask_data))
    {
        /* Local data path initalizations (by all data cores) */
        inic_data_local_init();

        cvmx_coremask_barrier_sync(coremask_data);

        /* Global data path initalizations (by first data core only) */
        if (cvmx_coremask_first_core(coremask_data))
	{
            inic_data_global_init(); /* Data Path */
	}
    }

#if !defined(CVM_COMBINED_APP_STACK)
    else
#endif

    if (cvmx_coremask_is_member(coremask_app)) 
    {
        /* Local application initalizations (by all app cores) */
        inic_app_local_init();
        cvmx_coremask_barrier_sync(coremask_app);

        /* Global application initalizations (by first app core only) */
        if (cvmx_coremask_first_core(coremask_app))
	{
            inic_app_global_init();
	}
    }

    cvmx_coremask_barrier_sync(coremask_all);

    if ((cvmx_get_core_num()) == 0x0)
    {
      printf("\nFPA buffer pool allocation:\n\n");
      cvm_common_fpa_display_all_pool_info();
    }

    cvmx_coremask_barrier_sync(coremask_all);


#if defined(CVM_COMBINED_APP_STACK)

    if (cvmx_coremask_first_core (coremask_data)) 
    {
        if (cvm_so_callbacks[CVM_SO_FNPTR_MAIN_GLOBAL] &&
	    (*((int (*) ())cvm_so_callbacks[CVM_SO_FNPTR_MAIN_GLOBAL])) ()) 
        {
	    printf ("Application main_global callback failed\n");
	    return (result);
        }
    }
    cvmx_coremask_barrier_sync (coremask_all);

    if (cvmx_coremask_is_member (coremask_data)) 
    {
        if (cvm_so_callbacks[CVM_SO_FNPTR_MAIN_LOCAL] &&
	    (*((int (*) ())cvm_so_callbacks[CVM_SO_FNPTR_MAIN_LOCAL])) ()) 
        {
	    printf ("Application main_local callback failed on core %llu\n", CAST64(cvmx_get_core_num ()));
	    return (result);
        }
    }

    printf("init::::::::::::::::	PAKCET:%llu,     WQE:%llu\n", cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(CVMX_FPA_PACKET_POOL)), cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(CVMX_FPA_WQE_POOL)));
    printf("----------------------------------------------------\n");
    cvmx_pow_tag_req_t current_tag;
    current_tag = cvmx_pow_get_current_tag();
    printf("+++++++++++++++%llX, %llX\n", current_tag.s.type, current_tag.s.tag);

    cvmx_coremask_barrier_sync (coremask_all);

#if defined(CVM_CLI_APP) && defined(REAL_HW)
    if (core_id == cvm_common_get_last_core(coremask_all))
    {
        cli();
    }
#endif
    //Renjs
    const int			coreid = cvmx_get_core_num(); 
    uint64_t			old_group_mask; 
    old_group_mask = cvmx_read_csr(CVMX_POW_PP_GRP_MSKX(coreid)); 
    cvmx_write_csr(CVMX_POW_PP_GRP_MSKX(coreid) ,old_group_mask  & ~(1<<10));


    if (cvmx_coremask_is_member (coremask_data)) 
    {
        inic_data_loop ();
    }

#else
    /* Now start the main loop on all cores */
    if (cvmx_coremask_is_member(coremask_data))
    {
#if defined(CVM_CLI_APP) && defined(REAL_HW)
        if (core_id == cvm_common_get_last_core(coremask_all)) 
        {
	    cli();
        }
#endif
	
	/* data */
        inic_data_loop();
    }


    else if(cvmx_coremask_is_member(coremask_app))
    {
        /* Application */
        inic_app_loop();
    }
#endif

#if defined(CVM_COMBINED_APP_STACK)
    if (cvmx_coremask_is_member (coremask_data)) 
    {
        if (cvm_so_callbacks[CVM_SO_FNPTR_EXIT_LOCAL] &&
	    (*((int (*) ())cvm_so_callbacks[CVM_SO_FNPTR_EXIT_LOCAL])) ()) 
        {
	    printf ("Application exit_local callback failed on core %llu\n", CAST64(cvmx_get_core_num ()));
	    return (result);
        }
    }
    cvmx_coremask_barrier_sync (coremask_all);

    if (cvmx_coremask_first_core (coremask_data)) 
    {
        if (cvm_so_callbacks[CVM_SO_FNPTR_EXIT_GLOBAL] &&
	    (*((int (*) ())cvm_so_callbacks[CVM_SO_FNPTR_EXIT_GLOBAL])) ()) 
        {
	    printf ("Application exit_global callback failed\n");
	    return (result);
        }
    }
    cvmx_coremask_barrier_sync (coremask_all);
#else
    /* We may never reach here, except on the application core */
    if(cvmx_coremask_is_member(coremask_data))
    {
        printf("Data path core exited\n");
        return(-1);
    }
    /*cvm_inic_shutdown();*/
    CVMX_BREAK;
#endif

    return (result);
}


/*
 *
 */
int inic_generic_local_init(void)
{
  /* do common local init */
  cvm_common_local_init();


  return 0;
}


/*
 * returns the version number based on CVS tag
 */
static inline const char *inic_get_version(void)
{
    static char version[80];
    const char *cavium_parse = "$Name: TCPIP_1_5_0_build_62 ";

    if (cavium_parse[7] == ' ')
    {
        snprintf(version, sizeof(version), "Internal %s", __DATE__);
    }
    else
    {
        char *major = NULL;
        char *minor1 = NULL;
        char *minor2 = NULL;
        char *build = NULL;
        char *buildnum = NULL;
        char *end = NULL;
        char buf[80];

        strncpy(buf, cavium_parse, sizeof(buf));
        buf[sizeof(buf)-1] = 0;

        major = strchr(buf, '_');
        if (major)
        {
            major++;
            minor1 = strchr(major, '_');
            if (minor1)
            {
                *minor1 = 0;
                minor1++;
                minor2 = strchr(minor1, '_');
                if (minor2)
                {
                    *minor2 = 0;
                    minor2++;
                    build = strchr(minor2, '_');
                    if (build)
                    {
                        *build = 0;
                        build++;
                        buildnum = strchr(build, '_');
                        if (buildnum)
                        {
                            *buildnum = 0;
                            buildnum++;
                            end = strchr(buildnum, ' ');
                            if (end)
                                *end = 0;
                        }
                    }
                }
            }
        }

        if (major && minor1 && minor2 && build && buildnum && (strcmp(build, "build") == 0))
            snprintf(version, sizeof(version), "%s.%s.%s, build %s", major, minor1, minor2, buildnum);
        else
            snprintf(version, sizeof(version), "%s", cavium_parse);
    }

    return version;
}

