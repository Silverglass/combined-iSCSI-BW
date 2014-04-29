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
#include <stdint.h>
#include <string.h>
#include <malloc.h>
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
#include "cvm-ip-route.h"
#include "cvm-ip-sockio.h"
#include "cvm-ip-inline.h"
#include "cvm-ip-config.h"
#include "cvm-ip-if-dl.h"

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-ip6.h"
#include "cvm-ip6-var.h"
#include "cvm-icmp6.h"
#include "cvm-scope6-var.h"
#include "cvm-ip6-inline.h"
#include "cvm-in6-var.h"
#endif

#include "cvm-tcp-var.h"

#include "socket.h"
#include "socketvar.h"
#include "cvm-socket.h"
#include "cvm-socket-raw.h"


#ifdef INET6
int sock_raw_application_v6(void);
/* int sock_raw_test_v6(void); */
#endif

#define RAW_PERF

#ifdef RAW_PERF
int raw_perf_application();
#ifdef INET6
int raw6_perf_application();
#endif
#endif

/* Print related defines */
#define CVM_RAW_PRINT_OFF         1
#define CVM_RAW_ONE_MILLION       1000000
#define CVM_RAW_PRINT_COUNT       1     /* CVM_RAW_ONE_MILLION */


/* Defines for selecting test mode */
/* #define SOCK_RAW_BSD_TEST */               /* bsd compliance (error codes) test */
#define SOCK_RAW_NON_BLOCKING_MODE            /* default non-blocking mode */


/* Blocking / Non-blocking mode */
#ifdef SOCK_RAW_NON_BLOCKING_MODE
#define SOCK_RAW_NON_BLOCKING_GLOBAL      1   /* 1 => non-blocking; 0 => blocking */
#else
#define SOCK_RAW_NON_BLOCKING_GLOBAL      0   /* 1 => non-blocking; 0 => blocking */
#endif

#define SOCK_RAW_NUM_INSTANCES_GLOBAL     1  /* SOCK_RAW_NUM_INSTANCES_MAX */
#define SOCK_RAW_NUM_INSTANCES_MAX        (SOCK_RAW_NUM_INSTANCES_GLOBAL + 10)

#define SOCK_RAW_NUM_SOCK_EXTRA           0     /* non-receiver sockets */
#define SOCK_RAW_NUM_SOCK                 3     /* receiver sockets     */
#define SOCK_RAW_NUM_SOCK_MAX             (SOCK_RAW_NUM_SOCK + SOCK_RAW_NUM_SOCK_EXTRA)
#define SOCK_RAW_TOTAL_NUM_SOCK           (SOCK_RAW_NUM_SOCK_MAX * SOCK_RAW_NUM_INSTANCES_MAX)

#define SOCK_RAW_BUF_MAX          (64*1024)
#define SOCK_RAW_RECV_BUF         SOCK_RAW_BUF_MAX
#define SOCK_RAW_SEND_BUF         SOCK_RAW_BUF_MAX

#define SOCK_RAW_PKT_LEN_MIN      1
#define SOCK_RAW_PKT_LEN_MAX      1480  /* max size without fragmentation = 1480 */
#define RAW_IP_HEADER_LEN         20

#define CVM_IP_IPPROTO_IPV4       4
#define CVM_IP_IPPROTO_4          4
#define CVM_IP_IPPROTO_150        150
#define CVM_IP_IPPROTO_160        160
#define CVM_IP_IPPROTO_170        170
#define CVM_IP_IPPROTO_180        180


/* Address related defines */
/* #define SOCK_RAW_LADDR      CVM_IP_INADDR_ANY */

/* Foreign address - BSD */
#define SOCK_RAW_FADDR_BSD_48     0xc0a83098   /* 192.168.48.152 */


/* Foreign address - remote machine */
#define SOCK_RAW_FADDR_48         0xc0a83034   /* 192.168.48.52 */
#define SOCK_RAW_FADDR_49         0xc0a83134   /* 192.168.49.52 */
#define SOCK_RAW_FADDR_50         0xc0a83234   /* 192.168.50.52 */
#define SOCK_RAW_FADDR_51         0xc0a83334   /* 192.168.51.52 */
#define SOCK_RAW_FADDR_100        0xc0a86434   /* 192.168.100.52 */


/* Foreign address (used by Octeon) */
#define SOCK_RAW_FADDR_PORT0      SOCK_RAW_FADDR_48
#define SOCK_RAW_FADDR_PORT1      SOCK_RAW_FADDR_49
#define SOCK_RAW_FADDR_PORT2      SOCK_RAW_FADDR_50
#define SOCK_RAW_FADDR_PORT3      SOCK_RAW_FADDR_51


/* Local address - Octeon */
#define SOCK_RAW_LADDR_PORT0      0xc0a83001   /* 192.168.48.1 */
#define SOCK_RAW_LADDR_PORT1      0xc0a83101   /* 192.168.49.1 */
#define SOCK_RAW_LADDR_PORT2      0xc0a83201   /* 192.168.50.1 */
#define SOCK_RAW_LADDR_PORT3      0xc0a83301   /* 192.168.51.1 */


/* 
 * Core configuration 
 */
#ifdef CVM_RAW_TCP_SUPPORT
#define SOCK_RAW_LPORT   0x1          
#define SOCK_RAW_FPORT   0x2         
#endif

#define SOCK_RAW_LADDR_CORE_0             SOCK_RAW_LADDR_PORT0
#define SOCK_RAW_FADDR_CORE_0             SOCK_RAW_FADDR_PORT0
#define SOCK_RAW_INSTANCES_CORE_0         SOCK_RAW_NUM_INSTANCES_GLOBAL
#define SOCK_RAW_IPPROTO_CORE_0           CVM_IP_IPPROTO_150 /* CVM_IP_IPPROTO_ICMP - for icmp testing */
#define SOCK_RAW_PKT_LEN_MIN_CORE_0       1
#define SOCK_RAW_PKT_LEN_MAX_CORE_0       1480
#define SOCK_RAW_IS_NON_BLOCKING_CORE_0   SOCK_RAW_NON_BLOCKING_GLOBAL
#define SOCK_RAW_BIND_FLAG_CORE_0         1
#define SOCK_RAW_CONNECT_FLAG_CORE_0      1

#define SOCK_RAW_LADDR_CORE_1             SOCK_RAW_LADDR_PORT1
#define SOCK_RAW_FADDR_CORE_1             SOCK_RAW_FADDR_PORT1
#define SOCK_RAW_INSTANCES_CORE_1         SOCK_RAW_NUM_INSTANCES_GLOBAL
#define SOCK_RAW_IPPROTO_CORE_1           CVM_IP_IPPROTO_160
#define SOCK_RAW_PKT_LEN_MIN_CORE_1       1
#define SOCK_RAW_PKT_LEN_MAX_CORE_1       1480
#define SOCK_RAW_IS_NON_BLOCKING_CORE_1   SOCK_RAW_NON_BLOCKING_GLOBAL
#define SOCK_RAW_BIND_FLAG_CORE_1         1
#define SOCK_RAW_CONNECT_FLAG_CORE_1      1

#define SOCK_RAW_LADDR_CORE_2             SOCK_RAW_LADDR_PORT2
#define SOCK_RAW_FADDR_CORE_2             SOCK_RAW_FADDR_PORT2
#define SOCK_RAW_INSTANCES_CORE_2         SOCK_RAW_NUM_INSTANCES_GLOBAL
#define SOCK_RAW_IPPROTO_CORE_2           CVM_IP_IPPROTO_170
#define SOCK_RAW_PKT_LEN_MIN_CORE_2       1
#define SOCK_RAW_PKT_LEN_MAX_CORE_2       1480
#define SOCK_RAW_IS_NON_BLOCKING_CORE_2   SOCK_RAW_NON_BLOCKING_GLOBAL
#define SOCK_RAW_BIND_FLAG_CORE_2         1
#define SOCK_RAW_CONNECT_FLAG_CORE_2      1

#define SOCK_RAW_LADDR_CORE_3             SOCK_RAW_LADDR_PORT3
#define SOCK_RAW_FADDR_CORE_3             SOCK_RAW_FADDR_PORT3
#define SOCK_RAW_INSTANCES_CORE_3         SOCK_RAW_NUM_INSTANCES_GLOBAL
#define SOCK_RAW_IPPROTO_CORE_3           CVM_IP_IPPROTO_180
#define SOCK_RAW_PKT_LEN_MIN_CORE_3       1
#define SOCK_RAW_PKT_LEN_MAX_CORE_3       1480
#define SOCK_RAW_IS_NON_BLOCKING_CORE_3   SOCK_RAW_NON_BLOCKING_GLOBAL
#define SOCK_RAW_BIND_FLAG_CORE_3         1
#define SOCK_RAW_CONNECT_FLAG_CORE_3      1


/*
 * configuration per instance 
 */
typedef struct _raw_instance 
{
    int      ipproto;
    uint8_t  bind_flag;
    uint8_t  connect_flag;
    int      num_sock_input;
    int      num_sock_cfg;
    int      is_non_blocking;
    int      pkt_len_min;
    int      pkt_len_max;
    int      fd[SOCK_RAW_NUM_SOCK_MAX];
    int      ip_hdrincl[SOCK_RAW_NUM_SOCK_MAX];
    cvm_raw_conn_info_t raw_conn[SOCK_RAW_NUM_SOCK_MAX];
} sock_raw_instance_t;


/*
 * configuration per core 
 */
typedef struct _raw_core_cfg
{
    uint8_t                core_id;
    uint32_t               laddr;
    uint32_t               faddr;
    uint16_t               lport;
    uint16_t               fport;
    int                    num_instances;
    sock_raw_instance_t    inst[SOCK_RAW_NUM_INSTANCES_MAX];
    cvm_so_status          sock_status[SOCK_RAW_NUM_SOCK_MAX];
    cvmx_spinlock_t        lock;
} sock_raw_core_cfg_t;



/* Function prototypes */

/**
 * Display the core configuration 
 */
void sock_raw_core_cfg_dump(sock_raw_core_cfg_t *cfg);

int  sock_raw_multicore_init(sock_raw_core_cfg_t *cfg);
int  sock_raw_instance_conn_init(sock_raw_instance_t *inst, uint32_t laddr, uint32_t faddr);
int  sock_raw_multicore_test();
void sock_raw_stress_test(sock_raw_core_cfg_t *cfg);

int  sock_raw_create  (sock_raw_core_cfg_t *cfg);
int  sock_raw_bind    (sock_raw_core_cfg_t *cfg);
int  sock_raw_connect (sock_raw_core_cfg_t *cfg);
void sock_raw_close   (sock_raw_core_cfg_t *cfg);

void sock_raw_getopt(sock_raw_core_cfg_t *cfg);
void sock_raw_setopt(sock_raw_core_cfg_t *cfg, int ip_hdrincl_val);
void sock_raw_options_test(sock_raw_core_cfg_t *cfg, int toggle, int test_flag);

int  sock_raw_blocking (sock_raw_core_cfg_t *cfg);
int  sock_raw_send(sock_raw_core_cfg_t *cfg, sock_raw_instance_t *inst, uint32_t faddr_recvfrom, 
                   uint8_t *in_data, int recv_payload_len, int which_sock, char *str, uint32_t *laddr_used);

void sock_raw_ip_hdr_fill(void *ptr, int recv_payload_len, uint32_t laddr, uint32_t faddr, uint16_t ipproto);
inline unsigned short sock_raw_ip_csum (unsigned short *buf, int nwords);

int cvm_raw_pkt_compare(void *ptr, int len);

/* non-blocking */
int sock_raw_build_poll_list(sock_raw_core_cfg_t *cfg, cvm_so_status *status_list);
int sock_raw_process_read   (sock_raw_core_cfg_t *cfg, cvm_so_status *status_list, int nfds);
int sock_raw_non_blocking (sock_raw_core_cfg_t *cfg);
int sock_raw_deal_with_data (sock_raw_core_cfg_t *cfg, uint32_t socket_id);


/* Functionality test - (BSD compliance, error codes testing) */
#ifdef SOCK_RAW_BSD_TEST
int sock_raw_bsd_compliance_test();
void sock_raw_bsd_send_error_test(int fd1, uint8_t bind_flag, uint32_t laddr, uint8_t connect_flag, uint32_t faddr, 
                      uint32_t sendto_faddr1, uint32_t sendto_faddr2, uint32_t sendto_faddr3, uint32_t sendto_faddr4);
#endif 

/* #define SOCK_RAW_CREATE_CLOSE_TEST */


extern char *inet_ntoa(struct cvm_ip_in_addr ina);


/**
 * server_application_raw:
 *
 * This routine
 * - raw sockets application (functions similar to a server)
 * - calls different routines for various test scenarios including stress test
 *   for blocking as well as non-blocking mode
 *
 * Return codes:
 * - none
 */
int server_application_raw()
{
    int retval = 0;

#ifdef RAW_PERF

#ifdef INET6
    raw6_perf_application();     /* v6 application */
    // raw_perf_application();   /* v4 application */
#else
    raw_perf_application();
#endif

    return 0;
#endif



#ifdef SOCK_RAW_BSD_TEST /* { */

    /* BSD compliance / error code testing */
    sock_raw_bsd_compliance_test();

#else /* } { */

    sock_raw_core_cfg_t core_cfg;

    memset(&core_cfg, 0, sizeof(sock_raw_core_cfg_t));
    retval = sock_raw_multicore_init(&core_cfg);
    if (retval != 0)
        return retval;


    retval = sock_raw_create(&core_cfg);
    if (retval != 0)
        return retval;
    sock_raw_bind(&core_cfg);
    sock_raw_connect(&core_cfg);

#if 0
    /* set/get ip_hdrincl socket option */
    {
        int toggle    = 1; 
        int test_flag = 0;
        sock_raw_options_test(&core_cfg, toggle, test_flag);
    }
#endif
    sock_raw_core_cfg_dump(&core_cfg);

    cvmx_wait(300 * 1000 * 1000);
    cvmx_wait(300 * 1000 * 1000);

    if (core_cfg.core_id == 0)
        cvm_raw_lookup_dump_all(1);

    cvmx_wait(300 * 1000 * 1000);
    cvmx_wait(300 * 1000 * 1000);

    printf ("%s: core_id %d, Raw sockets stress test (non-DNI mode)...\n", __FUNCTION__, core_cfg.core_id);
    sock_raw_stress_test(&core_cfg);

#endif /* } */


    while (1) 
    {
       ;
    } 

    return retval;
}



/**
 * sock_raw_multicore_init:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - initialize the main sock_raw_core_cfg_t structure for the application core.
 *
 * Return codes:
 * - CVM_RAW_NO_ERROR - no error
 * - (-1)             - core id is not an application core id
 */
int sock_raw_multicore_init (sock_raw_core_cfg_t *cfg)
{
    int retval = CVM_RAW_NO_ERROR;
    int i      = 0;

    cvmx_spinlock_init(&cfg->lock);
    cvmx_spinlock_lock(&cfg->lock);
    cfg->core_id = (uint8_t)cvmx_get_core_num();

    switch (cfg->core_id)
    {
        case 0: 
            cfg->laddr         = SOCK_RAW_LADDR_CORE_0;
            cfg->faddr         = SOCK_RAW_FADDR_CORE_0;
            cfg->num_instances = SOCK_RAW_INSTANCES_CORE_0;
            for (i=0; i<cfg->num_instances; ++i)
            {
                cfg->inst[i].ipproto          = SOCK_RAW_IPPROTO_CORE_0 + i;
                cfg->inst[i].pkt_len_min      = SOCK_RAW_PKT_LEN_MIN_CORE_0;
                cfg->inst[i].pkt_len_max      = SOCK_RAW_PKT_LEN_MAX_CORE_0;
                cfg->inst[i].is_non_blocking  = SOCK_RAW_IS_NON_BLOCKING_CORE_0;
                cfg->inst[i].bind_flag        = SOCK_RAW_BIND_FLAG_CORE_0;
                cfg->inst[i].connect_flag     = SOCK_RAW_CONNECT_FLAG_CORE_0;
                cfg->inst[i].num_sock_input   = SOCK_RAW_NUM_SOCK;
                cfg->inst[i].num_sock_cfg     = sock_raw_instance_conn_init(&cfg->inst[i], cfg->laddr, cfg->faddr);
            }
            break;

        case 1:
            cfg->laddr         = SOCK_RAW_LADDR_CORE_1;
            cfg->faddr         = SOCK_RAW_FADDR_CORE_1;
            cfg->num_instances = SOCK_RAW_INSTANCES_CORE_1;
            for (i=0; i<cfg->num_instances; ++i)
            {
                cfg->inst[i].ipproto          = SOCK_RAW_IPPROTO_CORE_1 + i;
                cfg->inst[i].pkt_len_min      = SOCK_RAW_PKT_LEN_MIN_CORE_1;
                cfg->inst[i].pkt_len_max      = SOCK_RAW_PKT_LEN_MAX_CORE_1;
                cfg->inst[i].is_non_blocking  = SOCK_RAW_IS_NON_BLOCKING_CORE_1;
                cfg->inst[i].bind_flag        = SOCK_RAW_BIND_FLAG_CORE_1;
                cfg->inst[i].connect_flag     = SOCK_RAW_CONNECT_FLAG_CORE_1;
                cfg->inst[i].num_sock_input   = SOCK_RAW_NUM_SOCK;
                cfg->inst[i].num_sock_cfg     = sock_raw_instance_conn_init(&cfg->inst[i], cfg->laddr, cfg->faddr);
            }
            break;

        case 2:
            cfg->laddr         = SOCK_RAW_LADDR_CORE_2;
            cfg->faddr         = SOCK_RAW_FADDR_CORE_2;
            cfg->num_instances = SOCK_RAW_INSTANCES_CORE_2;
            for (i=0; i<cfg->num_instances; ++i)
            {
                cfg->inst[i].ipproto          = SOCK_RAW_IPPROTO_CORE_2 + i;
                cfg->inst[i].pkt_len_min      = SOCK_RAW_PKT_LEN_MIN_CORE_2;
                cfg->inst[i].pkt_len_max      = SOCK_RAW_PKT_LEN_MAX_CORE_2;
                cfg->inst[i].is_non_blocking  = SOCK_RAW_IS_NON_BLOCKING_CORE_2;
                cfg->inst[i].bind_flag        = SOCK_RAW_BIND_FLAG_CORE_2;
                cfg->inst[i].connect_flag     = SOCK_RAW_CONNECT_FLAG_CORE_2;
                cfg->inst[i].num_sock_input   = SOCK_RAW_NUM_SOCK;
                cfg->inst[i].num_sock_cfg     = sock_raw_instance_conn_init(&cfg->inst[i], cfg->laddr, cfg->faddr);
            }
            break;

        case 3:
            cfg->laddr         = SOCK_RAW_LADDR_CORE_3;
            cfg->faddr         = SOCK_RAW_FADDR_CORE_3;
            cfg->num_instances = SOCK_RAW_INSTANCES_CORE_3;
            for (i=0; i<cfg->num_instances; ++i)
            {
                cfg->inst[i].ipproto          = SOCK_RAW_IPPROTO_CORE_3 + i;
                cfg->inst[i].pkt_len_min      = SOCK_RAW_PKT_LEN_MIN_CORE_3;
                cfg->inst[i].pkt_len_max      = SOCK_RAW_PKT_LEN_MAX_CORE_3;
                cfg->inst[i].is_non_blocking  = SOCK_RAW_IS_NON_BLOCKING_CORE_3;
                cfg->inst[i].bind_flag        = SOCK_RAW_BIND_FLAG_CORE_3;
                cfg->inst[i].connect_flag     = SOCK_RAW_CONNECT_FLAG_CORE_3;
                cfg->inst[i].num_sock_input   = SOCK_RAW_NUM_SOCK;
                cfg->inst[i].num_sock_cfg     = sock_raw_instance_conn_init(&cfg->inst[i], cfg->laddr, cfg->faddr);
            }
            break;

        default: 
            printf ("%s: ERROR: core_id %d... not initialized\n", __FUNCTION__, cfg->core_id);
            retval = -1;
            break;
    }

    cvmx_spinlock_unlock(&cfg->lock);
    return retval;
}



/**
 * sock_raw_instance_conn_init:
 * @inst  - pointer to instance configuration structure per core (sock_raw_instance_t)
 * @laddr - local address for this instance
 * @faddr - foreign address for this instance
 *
 * This routine
 * - initialize the instance for a particular core
 *
 * Return codes:
 * - num  - returns the number of sockets actually configured for this instance
 */
int sock_raw_instance_conn_init(sock_raw_instance_t *inst, uint32_t laddr, uint32_t faddr)
{
    int ipproto = inst->ipproto;
    int num     = 0;
    
    /* 
     * Note: 
     * - This sock_raw_conn_init is different from cvm_raw_hash_init in cvm-socket-raw.c file.
     * - cvm-socket-raw.c creates sockets with IPPROTO_IP too. 
     * - code below just uses ipproto (ipproto value for that instance_t)
     */

    if (inst->num_sock_input > 0)
    {
        while (1) 
        {
            inst->raw_conn[num].ipproto = ipproto;
            inst->raw_conn[num].laddr   = laddr;
            inst->raw_conn[num].faddr   = faddr;
            ++num;
            if (num == inst->num_sock_input) 
                break;

            inst->raw_conn[num].ipproto = ipproto;
            inst->raw_conn[num].laddr   = 0;
            inst->raw_conn[num].faddr   = 0;
            ++num;
            if (num == inst->num_sock_input) 
                break;
    
            inst->raw_conn[num].ipproto = ipproto;
            inst->raw_conn[num].laddr   = laddr;
            inst->raw_conn[num].faddr   = 0;
            ++num;
            if (num == inst->num_sock_input) 
                break;
    
            inst->raw_conn[num].ipproto = ipproto;
            inst->raw_conn[num].laddr   = 0;
            inst->raw_conn[num].faddr   = faddr;
            ++num;
            if (num == inst->num_sock_input) 
                break;
        }
    }
    
    if (SOCK_RAW_NUM_SOCK_EXTRA > 0)
    {
        int i = 0;
        for (i=0; i<SOCK_RAW_NUM_SOCK_EXTRA; ++i) 
        {
            inst->raw_conn[num + i].ipproto = 199;
            inst->raw_conn[num + i].laddr   = laddr;
            inst->raw_conn[num + i].faddr   = faddr;
        }
     }

     return num;
}



/**
 * sock_raw_core_cfg_dump:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - display the core configuration
 *
 * Return codes:
 * - none
 */
void sock_raw_core_cfg_dump(sock_raw_core_cfg_t *cfg)
{
    int x = 0;
    sock_raw_instance_t *inst = &cfg->inst[x];

    printf("core_id %u inst %d num_inst %d laddr 0x%llx faddr 0x%llx ipproto %d bind %d connect %d num_sock_cfg %d is_non_block %d\n\n",
        cfg->core_id, x, cfg->num_instances, CVM_COMMON_UCAST64(cfg->laddr), CVM_COMMON_UCAST64(cfg->faddr), inst->ipproto, 
        inst->bind_flag, inst->connect_flag, inst->num_sock_cfg, inst->is_non_blocking);
}



/**
 * sock_raw_create:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - creates all the sockets for all the instances for all the cores
 *
 * Return codes:
 * - CVM_RAW_NO_ERROR - success
 * - (-1)             - cvm_so_create returns error
 */
int sock_raw_create(sock_raw_core_cfg_t *cfg)
{
    int  retval    = CVM_RAW_NO_ERROR;
    int  sock_type = CVM_SO_SOCK_RAW;
    int  i = 0;
    int  x = 0;
    sock_raw_instance_t *inst;

    cvmx_spinlock_lock(&cfg->lock);
    for (x=0; x<cfg->num_instances; x++)
    {
        inst = &cfg->inst[x];
        for (i=0; i<inst->num_sock_cfg; i++) 
        {
            errno = -99;
            inst->fd[i] = cvm_so_socket(CVM_SO_AF_INET, sock_type, inst->raw_conn[i].ipproto);
            if (inst->fd[i] < 0)
            {
                printf(
                    "%s:ERROR cvm_so_socket ret %d, fd 0x%x type %s ipproto %d create FAILED... errno %d\n",
                    __FUNCTION__, retval, inst->fd[i], cvm_socktype2str[sock_type], inst->raw_conn[i].ipproto, errno);
                cvmx_spinlock_unlock(&cfg->lock);
                return (-1);
            }
            else
            {
                if (inst->is_non_blocking) 
                {
                    cvm_so_fcntl(inst->fd[i], FNONBIO, 1);
                }
    
                if (CVM_RAW_PRINT_OFF == 0)
                {
#if 0
                    printf("%s: core_id %u (%d) fd 0x%x type %s ipproto %d CREATED (%s mode)\n", 
                        __FUNCTION__, cfg->core_id, i, inst->fd[i], cvm_socktype2str[sock_type], inst->raw_conn[i].ipproto,
                        inst->is_non_blocking ? "Non-Blocking": "Blocking");
#endif
                }
            }
        } /* for loop */
    }
    cvmx_spinlock_unlock(&cfg->lock);

    return retval;
}



/**
 * sock_raw_bind:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - binds all the sockets depending on the bind_flag
 *
 * Return codes:
 * - CVM_RAW_NO_ERROR - success
 * - error code returned by cvm_so_bind
 */
int sock_raw_bind(sock_raw_core_cfg_t *cfg)
{
    int retval = CVM_RAW_NO_ERROR;
    int  i = 0;
    int  x = 0;
    sock_raw_instance_t *inst;
    struct cvm_ip_sockaddr_in laddr;

    laddr.sin_family = CVM_SO_AF_INET;
    laddr.sin_len    = sizeof(laddr);
    laddr.sin_port   = 0;

    /* Bind the socket */
    cvmx_spinlock_lock(&cfg->lock);
    for (x=0; x<cfg->num_instances; x++)
    {
        inst = &cfg->inst[x];
        if (inst->bind_flag) 
        {
            for (i=0; i<inst->num_sock_cfg; i++)
            {
                errno = -99;
#ifdef CVM_RAW_TCP_SUPPORT
                    if (inst->raw_conn[i].ipproto == CVM_IP_IPPROTO_TCP)
                    {
                        laddr.sin_addr.s_addr = cfg->laddr;
                        laddr.sin_port        = (cvmx_get_core_num() * 100) + SOCK_RAW_LPORT;
                    }
                    else
                    {
                        laddr.sin_addr.s_addr = inst->raw_conn[i].laddr;
                        laddr.sin_port        = 0;
                    }
#else
                    laddr.sin_addr.s_addr = inst->raw_conn[i].laddr;
#endif

                retval = cvm_so_bind(inst->fd[i], (struct cvm_so_sockaddr *)&laddr, sizeof(struct cvm_so_sockaddr));
                if (retval)
                {
                    printf("%s:ERROR so_bind ret %d, core_id %u fd 0x%x, laddr 0x%llx:%d, bind FAILED... errno %d\n",
                        __FUNCTION__, retval, cfg->core_id, inst->fd[i], CVM_COMMON_UCAST64(laddr.sin_addr.s_addr), laddr.sin_port, errno);
                }
                else
                {
                    if (CVM_RAW_PRINT_OFF == 0)
                    {
#if 0
                        printf("%s: core_id %u (%d) fd 0x%x BOUND 0x%X:%d\n",
                            __FUNCTION__, cfg->core_id, i, inst->fd[i], (uint32_t)laddr.sin_addr.s_addr, laddr.sin_port);
#endif
                    }
                    
                }
            }
        }
    }
    cvmx_spinlock_unlock(&cfg->lock);

    return retval;
}



/**
 * sock_raw_connect:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - connects all the sockets depending on the connect flag
 *
 * Return codes:
 * - CVM_RAW_NO_ERROR - success
 * - error code returned by cvm_so_connect
 */
int sock_raw_connect(sock_raw_core_cfg_t *cfg)
{
    int  retval   = CVM_RAW_NO_ERROR;
    int  i = 0;
    int  x = 0;
    sock_raw_instance_t *inst;
    struct cvm_ip_sockaddr_in faddr;

    /* Connect the socket */
    faddr.sin_family = CVM_SO_AF_INET;
    faddr.sin_len    = sizeof(faddr);
    faddr.sin_port   = 0;

    cvmx_spinlock_lock(&cfg->lock);
    for (x=0; x<cfg->num_instances; x++)
    {
        inst = &cfg->inst[x];
        if (inst->connect_flag) 
        {
            for (i=0; i<inst->num_sock_cfg; i++)
            {
                errno = -99;
                {
#ifdef CVM_RAW_TCP_SUPPORT
                    if (inst->raw_conn[i].ipproto == CVM_IP_IPPROTO_TCP)
                    {
                        faddr.sin_addr.s_addr = cfg->faddr;
                        faddr.sin_port        = (cvmx_get_core_num() * 100) + SOCK_RAW_FPORT;
                    }
                    else
                    {
                        faddr.sin_addr.s_addr = inst->raw_conn[i].faddr;
                        faddr.sin_port        = 0;
                    }
#else
                    faddr.sin_addr.s_addr = inst->raw_conn[i].faddr;
#endif
                    retval = cvm_so_connect(inst->fd[i], (struct cvm_so_sockaddr*)&faddr, sizeof(struct cvm_so_sockaddr));
                    if (retval)
                    {
                        printf("%s:ERROR so_connect ret %d, core_id %u fd 0x%x faddr 0x%llx::%d, connect FAILED... errno %d\n",
                            __FUNCTION__, retval, cfg->core_id, inst->fd[i], CVM_COMMON_UCAST64(faddr.sin_addr.s_addr), faddr.sin_port, errno);
                    }
                    else
                    {
                        if (CVM_RAW_PRINT_OFF == 0)
                        {
#if 0
                            printf("%s: core_id %u (%d) fd 0x%x CONNECTED 0x%x:%d\n",
                                __FUNCTION__, cfg->core_id, i, inst->fd[i], (uint32_t)faddr.sin_addr.s_addr, faddr.sin_port);
#endif
                        }
                    }
                }
            }
        }
    }
    cvmx_spinlock_unlock(&cfg->lock);

    return retval;
}



/**
 * sock_raw_close:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - closes all the sockets
 *
 * Return codes:
 * - None
 */
void sock_raw_close(sock_raw_core_cfg_t *cfg)
{
    int i = 0;
    int x = 0;
    sock_raw_instance_t *inst;

    for (x=0; x<cfg->num_instances; x++)
    {
        inst = &cfg->inst[x];
        for (i=0; i<inst->num_sock_cfg; i++)
        {
            cvm_so_close(inst->fd[i]);
        }
    }
}



/**
 * sock_raw_send:
 * @cfg              - pointer to core configuration structure (sock_raw_core_cfg_t)
 * @inst             - pointer to instance structure 
 * @faddr_recvfrom   - foreign address from where the packet was received
 * @in_data          - received data from the remote end 
 * @recv_payload_len - received data payload length
 * @which_sock       - index for the socket fd array
 *
 * This routine
 * - sends the received data back to the remote end
 * - if the ip_hdrincl flag is set, it prepends the ip header 
 * - if connect_flag is 0, it uses cvm_so_sendto 
 * - if connect_flag is 1 and faddr is non-zero, it uses cvm_so_send
 * - if connect_flag is 1 and faddr is zero, 
 *   - it first connects to foreign address from where the packet was recevied,  
 *   - then uses cvm_so_send to send the packet and 
 *   - then restores the original connect i.e. re-connects to faddr = 0

 * Return codes:
 * - send_len - number of bytes sent
 */
int sock_raw_send(sock_raw_core_cfg_t *cfg, sock_raw_instance_t *inst, uint32_t faddr_in, uint8_t *in_data, int recv_payload_len, int which_sock, char *str, uint32_t *laddr_used)
{
    uint8_t   *out_data      = NULL;
    int        send_len      = 0;
    int        out_len       = 0;
    int        i             = which_sock;
    int        retval;
    uint32_t   faddr_used    = 0;
    struct cvm_ip_sockaddr_in  faddr_cfg;
    struct cvm_ip_sockaddr_in  faddr_restore;
    struct cvm_ip_sockaddr_in  faddr_recvfrom;

    /* Use SendTO if connect_addr is zero */
    faddr_cfg.sin_family      = CVM_SO_AF_INET;
    faddr_cfg.sin_addr.s_addr = cfg->faddr;
    faddr_cfg.sin_port        = 0;
    faddr_cfg.sin_len         = sizeof(faddr_cfg);

    /* Used to restore faddr to cfg->raw_conn[i].faddr after re-connect */
    faddr_restore.sin_family      = CVM_SO_AF_INET;
    faddr_restore.sin_addr.s_addr = -1;   /* set this to cfg->raw_conn[i].faddr */
    faddr_restore.sin_port        = 0;
    faddr_restore.sin_len         = sizeof(faddr_restore);

    /* faddr from where data is received */
    faddr_recvfrom.sin_family      = CVM_SO_AF_INET;
    faddr_recvfrom.sin_addr.s_addr = faddr_in;
    faddr_recvfrom.sin_port        = 0;
    faddr_recvfrom.sin_len         = sizeof(faddr_recvfrom);

    out_data   = in_data + RAW_IP_HEADER_LEN;
    out_len    = recv_payload_len;

    *laddr_used = inst->raw_conn[i].laddr;
    if (inst->connect_flag == 0)  /* Use sendto and recvfrom faddr */
    {
        faddr_used = faddr_recvfrom.sin_addr.s_addr;
        if (inst->ip_hdrincl[i] != 0)
        {
            out_data   = in_data;
            out_len    = recv_payload_len + RAW_IP_HEADER_LEN;
            *laddr_used = cfg->laddr;
            sock_raw_ip_hdr_fill((void *)out_data, recv_payload_len, *laddr_used, faddr_used, inst->raw_conn[i].ipproto); 
        }
        send_len = cvm_so_sendto(inst->fd[i], (void*)out_data, out_len, 0,
                         (struct cvm_so_sockaddr *)&faddr_recvfrom, sizeof(struct cvm_so_sockaddr));
        strcpy(str, "SendTO  ");
    }
    else if ((inst->connect_flag == 1) && (inst->raw_conn[i].faddr != 0))  /* Use send */
    {
        faddr_used = inst->raw_conn[i].faddr;
        if (inst->ip_hdrincl[i] != 0)
        {
            out_data   = in_data;
            out_len    = recv_payload_len + RAW_IP_HEADER_LEN;
            *laddr_used = cfg->laddr;
            sock_raw_ip_hdr_fill((void *)out_data, recv_payload_len, *laddr_used, faddr_used, inst->raw_conn[i].ipproto);
        }
        send_len = cvm_so_send(inst->fd[i], (void*)out_data, out_len, 0);
        strcpy(str, "SEND    ");
    }
    else  /* ((connect_flag == 1) && (faddr == 0)) */  
    {
        /* Note:
         * Since connect is done, we have to use SEND. Sendto cannot be used. 
         * Therefore, first re-connect to fddr_cfg and then use send
         * Steps: 
         * (1) Connect to configured faddr i.e. faddr_cfg
         * (2) send
         * (3) Restore connect back to inst->raw_conn[i].faddr i.e. 0
         */

        errno = -99;
        retval = cvm_so_connect(inst->fd[i], (struct cvm_so_sockaddr*)&faddr_cfg, sizeof(struct cvm_so_sockaddr));
        if (retval)
        {
            printf("%s:ERROR so_connect ret %d, core_id %u fd 0x%x faddr 0x%llx::%d, RE-connect FAILED... errno %d\n",
                __FUNCTION__, retval, cfg->core_id, inst->fd[i], CVM_COMMON_UCAST64(faddr_cfg.sin_addr.s_addr), faddr_cfg.sin_port, errno);
        }
        else
        {
            if (CVM_RAW_PRINT_OFF == 0)
            {
                /* printf("%s: core_id %u (%d) fd 0x%x RE-connected 0x%x:%d\n",
                    __FUNCTION__, cfg->core_id, i, inst->fd[i], (uint32_t)faddr_cfg.sin_addr.s_addr, faddr_cfg.sin_port); */
            }
        }

        faddr_used = faddr_cfg.sin_addr.s_addr;
        if (inst->ip_hdrincl[i] != 0)
        {
            out_data   = in_data;
            out_len    = recv_payload_len + RAW_IP_HEADER_LEN;
            *laddr_used = cfg->laddr;
            sock_raw_ip_hdr_fill((void *)out_data, recv_payload_len, *laddr_used, faddr_used, inst->raw_conn[i].ipproto);
        }
        send_len = cvm_so_send(inst->fd[i], (void*)out_data, out_len, 0);
        strcpy(str, "SEND    ");


        /* Restore original connect */
        errno = -99;
        faddr_restore.sin_addr.s_addr = inst->raw_conn[i].faddr;
        retval = cvm_so_connect(inst->fd[i], (struct cvm_so_sockaddr*)&faddr_restore, sizeof(struct cvm_so_sockaddr));
        if (retval)
        {
            printf("%s:ERROR so_connect ret %d, core_id %u fd 0x%x faddr 0x%llx::%d, connect FAILED... errno %d\n",
                __FUNCTION__, retval, cfg->core_id, inst->fd[i], CVM_COMMON_UCAST64(faddr_restore.sin_addr.s_addr), faddr_restore.sin_port, errno);
        }
        else
        {
            if (CVM_RAW_PRINT_OFF == 0)
            {
                /* printf("%s: core_id %u (%d) fd 0x%x restore-CONNECT 0x%x:%d\n",
                    __FUNCTION__, cfg->core_id, i, inst->fd[i], (uint32_t)faddr_restore.sin_addr.s_addr, faddr_restore.sin_port); */
            }
        }
    }
   
    return send_len;
}



/**
 * sock_raw_stress_test:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - raw sockets stress test for blocking as well as non-blocking sockets
 *   depending on the configuration
 *
 * Return codes:
 * - None
 */
void sock_raw_stress_test(sock_raw_core_cfg_t *cfg)
{
   uint8_t x = 0;
   sock_raw_instance_t *inst;

   for (x=0; x<cfg->num_instances; x++)
   {
       inst = &cfg->inst[x];
       if (inst->is_non_blocking)
       {
           printf ("\n%s: core_id %u Starting non-blocking mode test... \n",
               __FUNCTION__, cfg->core_id);
           sock_raw_non_blocking(cfg);
       }
       else 
       {
           printf ("\n%s: core_id %u Starting blocking mode test... \n",
               __FUNCTION__, cfg->core_id);
           sock_raw_blocking(cfg);
       }
   }
}


/**
 * sock_raw_blocking:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - raw sockets test application for blocking sockets
 * - receives the data from the remote end (using recv or recvfrom)
 * - sends this data back to the remote end
 * - checks for bind_flag, connect_flag, ip_hdrincl flag
 *
 * Return codes:
 * - 0
 */
int sock_raw_blocking(sock_raw_core_cfg_t *cfg)
{
    uint8_t    in_data[SOCK_RAW_BUF_MAX];
    uint64_t   num_pkts_recv    = 0;
    uint64_t   num_pkts_send    = 0;
    int        recv_len         = 0;
    int        recv_payload_len = 0;
    int        send_len         = 0;
    int        i                = 0;
    int        x                = 0;
    cvm_so_socklen_t addr_len   = 0;
    uint32_t   faddr_used       = 0;
    uint32_t   laddr_used       = 0;
    char       str[10];              /* SEND or SendTO */

    struct cvm_ip_sockaddr_in  faddr_recvfrom;
    sock_raw_instance_t       *inst;

    if (cfg == NULL) 
    {
        printf ("%s: ERROR cfg 0x%llx (NULL)\n", 
            __FUNCTION__, CAST64(cfg));
        return -1;
    }

    memset(in_data, 0, SOCK_RAW_BUF_MAX);


    while (1)
    {
      for (x=0; x<cfg->num_instances; x++)
      {
        inst = &cfg->inst[x];

        for (i=0; i<inst->num_sock_cfg; i++)
        {
            errno = -99;

            if ((inst->connect_flag == 0) ||
                ((inst->connect_flag == 1) && (inst->raw_conn[i].faddr == 0)))
            {
                recv_len   = cvm_so_recvfrom(inst->fd[i], (void*)in_data, SOCK_RAW_BUF_MAX, 0, 
                                             (struct cvm_so_sockaddr *)&faddr_recvfrom, &addr_len);
                faddr_used = faddr_recvfrom.sin_addr.s_addr;
            }
            else  /* ((inst->connect_flag == 1) || (inst->raw_conn[i].faddr != 0)) */
            {
                recv_len   = cvm_so_recv(inst->fd[i], (void*)in_data, SOCK_RAW_BUF_MAX, 0);
                faddr_used = inst->raw_conn[i].faddr;
            }

            {
                static int flag = 1;
                if (flag == 1)
                {
                    cvmx_wait(3 * 1000 * 1000);
                    flag = 0;
                }
            }

            recv_payload_len = recv_len - RAW_IP_HEADER_LEN;
            if (recv_payload_len >= 0)
            {
                ++num_pkts_recv;

                if (CVM_RAW_PRINT_OFF == 0) 
                {
                    if ((CVM_RAW_PRINT_COUNT == 1) || ((num_pkts_recv % CVM_RAW_PRINT_COUNT) == 0))
                    {
                        printf ("%s: core_id %u %s pkt %lld recv_len %d fd 0x%x laddr 0x%llx faddr_used 0x%llx ipproto %d\n",
                            __FUNCTION__, cfg->core_id, (inst->connect_flag == 0) ? "RECVFROM" : "RECV    ",
                            CAST64(num_pkts_recv), recv_payload_len, inst->fd[i], 
                            CVM_COMMON_UCAST64(inst->raw_conn[i].laddr), CVM_COMMON_UCAST64(faddr_used), inst->raw_conn[i].ipproto);
                    }
                }

                send_len = sock_raw_send(cfg, inst, faddr_used, (uint8_t *)in_data, recv_payload_len, i, &str[0], &laddr_used);
                if (send_len == -1)
                {
                    printf ("%s: ERROR core_id %u %s FAILED err %d... fd 0x%x send_len %d laddr 0x%llx faddr_used 0x%llx ipproto %d... errno %d\n",
                        __FUNCTION__, cfg->core_id, str, errno, inst->fd[i], send_len, 
                        CVM_COMMON_UCAST64(laddr_used), CVM_COMMON_UCAST64(faddr_used), inst->raw_conn[i].ipproto, errno);
                    return -1;
                }
                else
                {
                    ++num_pkts_send;

                    if (CVM_RAW_PRINT_OFF == 0) 
                    {
                        if ((CVM_RAW_PRINT_COUNT == 1) || ((num_pkts_recv % CVM_RAW_PRINT_COUNT) == 0))
                        {
                            printf ("%s: core_id %u %s pkt %lld send_len %d fd 0x%x laddr 0x%llx faddr_used 0x%llx ipproto %d\n",
                                __FUNCTION__, cfg->core_id, str, CAST64(num_pkts_send), send_len, inst->fd[i], 
                                CVM_COMMON_UCAST64(laddr_used), CVM_COMMON_UCAST64(faddr_used), inst->raw_conn[i].ipproto);
                        }
                    }
                }
            }
            else
            {
                /*
                printf ("%s: ERROR core_id %u RECV FAILED err %d... fd 0x%x recv_payload_len %d laddr 0x%llx faddr 0x%llx ipproto %d... errno %d\n",
                    __FUNCTION__, cfg->core_id, errno, inst->fd[i], recv_payload_len, 
                    CVM_COMMON_UCAST64(inst->raw_conn[i].laddr), CVM_COMMON_UCAST64(inst->raw_conn[i].faddr), inst->raw_conn[i].ipproto, errno);
                */
            }
        }  /* for num_sock_cfg */
      }  /* for instances */
    } /* while (1) */

    return 0;
}



/**
 * sock_raw_build_poll_list:
 * @cfg         - pointer to core configuration structure (sock_raw_core_cfg_t)
 * @status_list - pointer to cvm_so_status structure
 *
 * This routine
 * - is used by raw sockets non-blocking application
 * - builds the list of sockets to be polled 
 *
 * Return codes:
 * - fd_count - # sockets to be polled (# sockets in the polling list)
 */
int sock_raw_build_poll_list(sock_raw_core_cfg_t *cfg, cvm_so_status *status_list)
{
    int fd_count = 0;
    int i = 0;
    int x = 0;
    sock_raw_instance_t *inst;

    for (x=0; x<cfg->num_instances; x++)
    {
        inst = &cfg->inst[x];
        for (i=0; i<inst->num_sock_cfg; i++)
        {
            if ((inst->is_non_blocking) && (inst->fd[i] != 0))
            {
                status_list[fd_count].socket_id       = inst->fd[i];
                status_list[fd_count].read_ready      = 0;
                status_list[fd_count].write_ready     = 0;
                status_list[fd_count].exception_ready = 0;
                status_list[fd_count].reserved        = i;
                fd_count++;
            }
        }
    }

    return (fd_count);
}


/**
 * sock_raw_process_read:
 * @cfg         - pointer to core configuration structure (sock_raw_core_cfg_t)
 * @status_list - pointer to cvm_so_status structure
 * @nfds        - number of sockets in the polling list
 *
 * This routine
 * - processes the data, if available
 *
 * Return codes:
 * - 0
 */
int sock_raw_process_read (sock_raw_core_cfg_t *cfg, cvm_so_status *status_list, int nfds)
{
    int i = 0;

    for (i=0; i<nfds; i++)
    {
        if (status_list[i].read_ready)
        {
            sock_raw_deal_with_data(cfg, status_list[i].socket_id);
        }
    }

    return (0);
}



/**
 * sock_raw_deal_with_data:
 * @cfg       - pointer to core configuration structure (sock_raw_core_cfg_t)
 * @socket_id - socket fd
 *
 * This routine
 * - recv the data
 * - send it back to the remote end using sock_raw_send routine
 *
 * Return codes:
 * - 0
 */
int sock_raw_deal_with_data (sock_raw_core_cfg_t *cfg, uint32_t socket_id)
{
    uint8_t in_data[SOCK_RAW_BUF_MAX];
    int recv_payload_len = 0;
    int recv_len = 0;
    int send_len = 0;
    int error    = -1;
    int fd       = socket_id;
    static uint64_t num_pkts_recv = 0;
    static uint64_t num_pkts_send = 0;
    struct cvm_ip_sockaddr_in faddr_recvfrom;
    cvm_so_socklen_t addr_len;
    uint32_t faddr_used;
    uint32_t laddr_used;
    int i = 0;
    int x = 0;
    sock_raw_instance_t *inst = NULL;
    sock_raw_instance_t *matching_inst = NULL;
    int matching_i = 0;
    char str[10];

    for (x=0; x<cfg->num_instances; x++)
    {
        inst = &cfg->inst[x];
        for (i=0; i<inst->num_sock_cfg; i++)
        {
            if (inst->fd[i] == (int)socket_id)
            {
                matching_inst = inst;
                matching_i    = i;
            }
        }
    }

    errno = -99;

    if ((matching_inst->connect_flag == 0) ||
        ((matching_inst->connect_flag == 1) && (matching_inst->raw_conn[i].faddr == 0)))  /* See Note 2 below */
    {
        recv_len   = cvm_so_recvfrom(fd, (void*)in_data, SOCK_RAW_BUF_MAX, 0,
                                     (struct cvm_so_sockaddr *)&faddr_recvfrom, &addr_len);
        faddr_used = faddr_recvfrom.sin_addr.s_addr;
    }
    else  /* ((matching_inst->connect_flag == 1) || (matching_inst->raw_conn[i].faddr != 0)) */
    {
        recv_len   = cvm_so_recv(fd, (void*)in_data, SOCK_RAW_BUF_MAX, 0);
        faddr_used = matching_inst->raw_conn[matching_i].faddr;
    }
    recv_payload_len = recv_len - RAW_IP_HEADER_LEN;

    if (recv_len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, 
            "%s: (%lld) fd 0x%x recv FAILED... errno %d", 
            __FUNCTION__, CAST64(num_pkts_recv), fd, errno);
        return (error);
    }

    if (recv_len == 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, 
           "%s: fd 0x%x connection terminated\n",
           __FUNCTION__, fd);
        return (error);
    }

    if (CVM_RAW_PRINT_OFF == 0)
    {
        if ((CVM_RAW_PRINT_COUNT == 1) || ((num_pkts_recv % CVM_RAW_PRINT_COUNT) == 0))
        {
            printf ("%s: core_id %u %s pkt %lld recv_len %d fd 0x%x laddr 0x%llx faddr_used 0x%llx ipproto %d\n",
                __FUNCTION__, cfg->core_id, (matching_inst->connect_flag == 0) ? "RECVFROM" : "RECV    ",
                CAST64(num_pkts_recv), recv_payload_len, matching_inst->fd[matching_i],
                CVM_COMMON_UCAST64(matching_inst->raw_conn[matching_i].laddr), CVM_COMMON_UCAST64(faddr_used), matching_inst->raw_conn[matching_i].ipproto);
        }
    }

    ++num_pkts_recv;

do_send_again:


    send_len = sock_raw_send(cfg, matching_inst, faddr_recvfrom.sin_addr.s_addr, (uint8_t *)in_data, recv_payload_len, matching_i, str, &laddr_used);
    if (send_len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, 
            "%s: fd 0x%x send FAILED... errno %d", __FUNCTION__, fd, errno);
        if (errno == CVM_COMMON_EAGAIN)
        {
            goto do_send_again;
        }
        return (send_len);
    }

    if (CVM_RAW_PRINT_OFF == 0)
    {
        if ((CVM_RAW_PRINT_COUNT == 1) || ((num_pkts_recv % CVM_RAW_PRINT_COUNT) == 0))
        {
            printf ("%s: core_id %u %s pkt %lld send_len %d fd 0x%x faddr_used 0x%llx laddr_used 0x%llx ipproto %d\n",
                __FUNCTION__, cfg->core_id, str, CAST64(num_pkts_send), send_len, matching_inst->fd[matching_i],
                CVM_COMMON_UCAST64(faddr_used), CVM_COMMON_UCAST64(laddr_used), matching_inst->raw_conn[matching_i].ipproto);
        }
    }
    ++num_pkts_send;

    return (0);
}


/**
 * sock_raw_non_blocking:
 * @cfg         - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - receives the data from the remote end (using recv or recvfrom)
 * - sends it back to the remote end using sock_raw_send routine
 *
 * Return codes:
 * - 0
 */
int sock_raw_non_blocking(sock_raw_core_cfg_t *cfg)
{
    int no_of_fds_to_poll;
    cvm_so_status sock_status[SOCK_RAW_TOTAL_NUM_SOCK];
    int error; 

    while (1) 
    {
        no_of_fds_to_poll = sock_raw_build_poll_list(cfg, &sock_status[0]);
        error = cvm_so_poll(no_of_fds_to_poll, &sock_status[0], (struct timeval*)0);
        if (error < 0)
        {
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, 
                "%s: cvm_so_poll FAILED errno %d\n", __FUNCTION__, errno);
            return (0);
        }

        if (error == 0)
        {
            /* nothing read - should never happen when the timeout value of poll is 0 */
            /* printf("%s: Nothing is ready yet\n", __FUNCTION__); */
        }
        else
        {
            sock_raw_process_read(cfg, &sock_status[0], no_of_fds_to_poll);
        }
    }
    
    return 0;
}



/**
 * sock_raw_options_test:
 * @cfg       - pointer to core configuration structure (sock_raw_core_cfg_t)
 * @toggle    - toggles the ip_hdrincl flag every 2 sockets
 * @test_flag - used to test set/get options
 *
 * This routine
 * - gets the initial value of CVM_SO_SO_IP_HDRINCL option (using sock_raw_getopt routine)
 * - sets it (using sock_raw_setopt routine)
 * - gets it to verify that the option was set correctly (using sock_raw_getopt routine)
 *
 * Return codes:
 * - 0
 */
void sock_raw_options_test(sock_raw_core_cfg_t *cfg, int toggle, int test_flag)
{
    int   retval        = CVM_RAW_NO_ERROR;
    int   level         = CVM_SO_SOL_IP;
    int   optname       = CVM_SO_SO_IP_HDRINCL;
    int   optval        = 0;
    int   optval_get_prev = -1;
    int   optval_get    = -1;
    int   i = 0;
    int   x = 0;
    cvm_so_socklen_t optlen = sizeof(optval);
    sock_raw_instance_t *inst;

    cvmx_spinlock_lock(&cfg->lock);
    optval = 0;
    for (x=0; x<cfg->num_instances; x++)
    {
      inst = &cfg->inst[x];
      for (i=0; i<inst->num_sock_cfg; i++)
      {
        if (toggle) 
            optval = (i & 0x2) >> 1;
        else if (test_flag)
            optval = i;

        retval = cvm_so_getsockopt (inst->fd[i], level, optname, (void *)&optval_get_prev, &optlen);
        retval = cvm_so_setsockopt (inst->fd[i], level, optname, (const void *)&optval, optlen);
        retval = cvm_so_getsockopt (inst->fd[i], level, optname, (void *)&optval_get, &optlen);
        inst->ip_hdrincl[i] = optval_get;

        if (CVM_RAW_PRINT_OFF == 0)
        {
#if 0
            printf ("%s: >>>>>>>>>>>(%d) ip_hdrincl GET 0x%x SET 0x%x GET 0x%x (inst->ip_hdrincl 0x%x)\n", 
                __FUNCTION__, i, optval_get_prev, optval, optval_get, inst->ip_hdrincl[i]);
#endif
        }
      }
    }
    cvmx_spinlock_unlock(&cfg->lock);

    if (test_flag) 
    {
        cvmx_wait(3 * 1000 * 1000);
        cvmx_wait(3 * 1000 * 1000);
        cvmx_wait(3 * 1000 * 1000);
    }
}


/**
 * sock_raw_getopt:
 * @cfg  - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - gets the value of CVM_SO_SO_IP_HDRINCL option
 *
 * Return codes:
 * - None
 */
void sock_raw_getopt(sock_raw_core_cfg_t *cfg)
{
    int retval  = CVM_RAW_NO_ERROR;
    int level   = CVM_SO_SOL_IP;
    int optname = CVM_SO_SO_IP_HDRINCL;
    int optval  = -1;
    cvm_so_socklen_t optlen  = sizeof(optval);
    int i = 0;
    int x = 0;
    sock_raw_instance_t *inst;

    cvmx_spinlock_lock(&cfg->lock);
    for (x=0; x<cfg->num_instances; x++)
    {
      inst = &cfg->inst[x];
      for (i=0; i<inst->num_sock_cfg; i++) 
      {
        retval = cvm_so_getsockopt (inst->fd[i], level, optname, (void *)&optval, (cvm_so_socklen_t *)&optlen);
        printf ("%s: core_id %u fd 0x%x level %d optname %d optval 0x%x optlen %d retval %d\n",
            __FUNCTION__, cfg->core_id, inst->fd[i], level, optname, optval, (unsigned int)optlen, retval);
        inst->ip_hdrincl[i] = optval;
      }
    }
    cvmx_spinlock_unlock(&cfg->lock);
}



/**
 * sock_raw_setopt:
 * @cfg  - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - sets the value of CVM_SO_SO_IP_HDRINCL option
 *
 * Return codes:
 * - None
 */
void sock_raw_setopt(sock_raw_core_cfg_t *cfg, int optval)
{
    int retval  = CVM_RAW_NO_ERROR;
    int level   = CVM_SO_SOL_IP;
    int optname = CVM_SO_SO_IP_HDRINCL;
    cvm_so_socklen_t optlen  = sizeof(optval);
    int i = 0;
    int x = 0;
    sock_raw_instance_t *inst;

    cvmx_spinlock_lock(&cfg->lock);
    for (x=0; x<cfg->num_instances; x++)
    {
      inst = &cfg->inst[x];
      for (i=0; i<inst->num_sock_cfg; i++)
      {
        retval = cvm_so_setsockopt (inst->fd[i], level, optname, (const void *)&optval, optlen);
        printf ("%s: core_id %u fd 0x%x level %d optname %d optval 0x%x optlen %d retval %d\n",
            __FUNCTION__, cfg->core_id, inst->fd[i], level, optname, optval, (unsigned int)optlen, retval);
      }
    }
    cvmx_spinlock_unlock(&cfg->lock);
}



/**
 * sock_raw_ip_hdr_fill:
 * @ptr              - void pointer for filling-in the ip header
 * @recv_payload_len - recv payload length
 * @laddr            - local address
 * @faddr            - foreign address
 * @ipproto          -  protocol field value
 *
 * This routine
 * - fill-in the ip header
 *
 * Return codes:
 * - None
 */
void sock_raw_ip_hdr_fill(void *ptr, int recv_payload_len, uint32_t laddr, uint32_t faddr, uint16_t ipproto)
{
    cvm_ip_ip_t *ip = (cvm_ip_ip_t *)ptr;

    ip->ip_v          = CVM_IP_IPVERSION;
    ip->ip_hl         = 5;
    ip->ip_tos        = 0;
    ip->ip_len        = recv_payload_len + RAW_IP_HEADER_LEN;
    ip->ip_id         = 0;
    ip->ip_off        = 0;
    ip->ip_ttl        = 0xff;
    ip->ip_sum        = 0;
    ip->ip_p          = ipproto;
    ip->ip_src.s_addr = laddr;
    ip->ip_dst.s_addr = faddr;

    ip->ip_sum = sock_raw_ip_csum((unsigned short *) ptr, ip->ip_len>>1);
}



/**
 * sock_raw_ip_csum:
 * @buf    - pointer the ip header buffer
 * @nwords  - number of words in the header (16-bit words)
 *
 * This routine
 * - generates the checksum for ip header
 *
 * Return codes:
 * - unsigned short - ip checksum value
 */
inline unsigned short sock_raw_ip_csum (unsigned short *buf, int nwords)
{
    unsigned long sum;

    for (sum=0; nwords>0; nwords--) 
    {
            sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = sum + (sum >> 16);
    return (unsigned short) (~sum);
}



/**
 * cvm_raw_pkt_compare:
 * @ptr  - void pointer containing the data bytes to be verified
 * @len  - number of bytes to be verified
 * This routine
 * - compares the contents of void ptr with increasing number sequence (0 to len)
 *
 * Return codes:
 * - (-1) - data mismatch error
 * - 0    - no error (no data mismatch)
 */
int cvm_raw_pkt_compare(void *ptr, int len)
{
    uint8_t *data = (uint8_t *)ptr;
    int i = 0;
    int retval = 0;

    for (i=0; i<len; i++)
    {
        if  ((*(data+i)) != (i & 0xFF))
        {
            printf("Byte mismatch data[%d]=0x%x expected 0x%x\n", i, (*(data+i)), (i & 0xFF));
            retval = -1;
        }
    }

    return retval;
}

#ifdef RAW_PERF

/* 
 * Non-DNI mode:
 * sockets = 6400 | ports =  4 | num_faddr = 8 | ipproto = 200 (25 per core) ==>  4 * 8 * 200 = 6400
 * sockets = 6720 | ports = 14 | num_faddr = 3 | ipproto = 160 (20 per core) ==> 14 * 3 * 160 = 6720 
 * sockets = 8400 | ports = 14 | num_faddr = 3 | ipproto = 200 (25 per core) ==> 14 * 3 * 200 = 8400 
 */

/* #define RAW_PERF_TEST_ALL_ZEROS */
#define RAW_PERF_TEST_RECV_SEND
 
#define RAW_PERF_NUM_APP_CORES_MAX    15
#define RAW_PERF_NUM_APP_CORES        NUM_APP_PROCESSORS  /* NOTE: Make sure this value is same as # App Cores used */

#define RAW_PERF_DATA_BUFFER_SIZE     65535
#define RAW_PERF_IP_HEADER_LEN        20
#define RAW_PERF_IPPROTO_BASE         50
#define RAW_PERF_NUM_PORTS_MAX        14 
#define RAW_PERF_NUM_PORTS            4  /* RAW_PERF_NUM_PORTS_MAX */
#define RAW_PERF_NUM_FADDR            8

#ifdef CVM_RAW_TCP_SUPPORT
    #define RAW_PERF_TCP_LPORT        1
    #define RAW_PERF_TCP_FPORT        2 
    #define RAW_PERF_TCP_FILLER_SOCKETS_PER_PORT   0  /* per port per core */
#else
    #define RAW_PERF_TCP_LPORT        0
    #define RAW_PERF_TCP_FPORT        0
    #define RAW_PERF_TCP_FILLER_SOCKETS_PER_PORT   0
#endif

#define RAW_PERF_SOCKETS_PER_PORT      1  /* sockets per port per core */ /* eg. 50 for 4 app cores, 25 for 8 app cores, 200 for 1 app core */
#define RAW_PERF_MAX_SOCKETS_PER_PORT (RAW_PERF_SOCKETS_PER_PORT + RAW_PERF_TCP_FILLER_SOCKETS_PER_PORT)  /* total # of sockets per port per core */

#define RAW_PERF_TCP_FILLER_SOCKETS   (RAW_PERF_TCP_FILLER_SOCKETS_PER_PORT * RAW_PERF_NUM_PORTS * RAW_PERF_NUM_APP_CORES)
#define RAW_PERF_MAX_SOCKETS          (RAW_PERF_MAX_SOCKETS_PER_PORT * RAW_PERF_NUM_PORTS * RAW_PERF_NUM_APP_CORES)  /* total # of sockets */

/* Foreign address - remote machine */
#define RAW_PERF_FADDR_PORT0      0xc0a82034   /* 192.168.32.52 */
#define RAW_PERF_FADDR_PORT1      0xc0a82134   /* 192.168.33.52 */
#define RAW_PERF_FADDR_PORT2      0xc0a82234   /* 192.168.34.52 */
#define RAW_PERF_FADDR_PORT3      0xc0a82334   /* 192.168.35.52 */
#define RAW_PERF_FADDR_PORT4      0xc0a82434   /* 192.168.36.52 */
#define RAW_PERF_FADDR_PORT5      0xc0a82534   /* 192.168.37.52 */
#define RAW_PERF_FADDR_PORT6      0xc0a82634   /* 192.168.38.52 */
#define RAW_PERF_FADDR_PORT7      0xc0a82734   /* 192.168.39.52 */
#define RAW_PERF_FADDR_PORT8      0xc0a82834   /* 192.168.40.52 */
#define RAW_PERF_FADDR_PORT9      0xc0a82934   /* 192.168.41.52 */
#define RAW_PERF_FADDR_PORT48     0xc0a83034   /* 192.168.48.52 */
#define RAW_PERF_FADDR_PORT49     0xc0a83134   /* 192.168.49.52 */
#define RAW_PERF_FADDR_PORT50     0xc0a83234   /* 192.168.50.52 */
#define RAW_PERF_FADDR_PORT51     0xc0a83334   /* 192.168.51.52 */

/* Local address */
#define RAW_PERF_LADDR_PORT0      0xc0a82001   /* 192.168.32.1 */
#define RAW_PERF_LADDR_PORT1      0xc0a82101   /* 192.168.33.1 */
#define RAW_PERF_LADDR_PORT2      0xc0a82201   /* 192.168.34.1 */
#define RAW_PERF_LADDR_PORT3      0xc0a82301   /* 192.168.35.1 */
#define RAW_PERF_LADDR_PORT4      0xc0a82401   /* 192.168.36.1 */
#define RAW_PERF_LADDR_PORT5      0xc0a82501   /* 192.168.37.1 */
#define RAW_PERF_LADDR_PORT6      0xc0a82601   /* 192.168.38.1 */
#define RAW_PERF_LADDR_PORT7      0xc0a82701   /* 192.168.39.1 */
#define RAW_PERF_LADDR_PORT8      0xc0a82801   /* 192.168.40.1 */
#define RAW_PERF_LADDR_PORT9      0xc0a82901   /* 192.168.41.1 */
#define RAW_PERF_LADDR_PORT48     0xc0a83001   /* 192.168.48.1 */
#define RAW_PERF_LADDR_PORT49     0xc0a83101   /* 192.168.49.1 */
#define RAW_PERF_LADDR_PORT50     0xc0a83201   /* 192.168.50.1 */
#define RAW_PERF_LADDR_PORT51     0xc0a83301   /* 192.168.51.1 */

typedef struct _raw_perf_socket_info
{
   int                       fd;
   struct cvm_ip_sockaddr_in addr;
   int                       addrlen;
   int                       mode;
} raw_perf_socket_info_t;


typedef struct _raw_perf_sockets
{
    int free_count;
    raw_perf_socket_info_t sock[RAW_PERF_MAX_SOCKETS];
} raw_perf_sockets_t;


int raw_perf_build_poll_list(cvm_so_status* list, raw_perf_sockets_t* sockets, int max);
int raw_perf_process_read(cvm_so_status* status_list, int nfds, raw_perf_sockets_t* sockets);
int raw_perf_deal_with_data(raw_perf_sockets_t* sockets, int index);
void raw_perf_poll_list_dump(cvm_so_status *list, int no_of_fds_to_poll, int dump_all_flag);

#ifdef CVM_RAW_TCP_SUPPORT
int raw_perf_tcp_filler_sockets();
#endif


/**
 * Raw socket application (optimized for performance)
 */
int raw_perf_application()
{
    int raw_perf_all_zeros_flag = 0;

    raw_perf_sockets_t raw_sockets;
    int core_id = -1;
    int no_of_fds_to_poll = 0;
    int error;
#ifdef RAW_PERF_TEST_RECV_SEND
    int retval;
#endif
    int n = 0;
    int ff = 0;
    int num_sock = 0;
    int port = 0;
    int raw_ipproto_base = 0;
    int ipproto = 0;
    cvm_so_status sock_status[RAW_PERF_MAX_SOCKETS];
    struct cvm_ip_sockaddr_in laddr;
    struct cvm_ip_sockaddr_in faddr;
    uint32_t RAW_PERF_LADDR[RAW_PERF_NUM_PORTS_MAX] = { 
        RAW_PERF_LADDR_PORT48, RAW_PERF_LADDR_PORT49, RAW_PERF_LADDR_PORT50, RAW_PERF_LADDR_PORT51, 
        RAW_PERF_LADDR_PORT0,  RAW_PERF_LADDR_PORT1,  RAW_PERF_LADDR_PORT2,  RAW_PERF_LADDR_PORT3,
        RAW_PERF_LADDR_PORT4,  RAW_PERF_LADDR_PORT5,  RAW_PERF_LADDR_PORT6,  RAW_PERF_LADDR_PORT7, 
        RAW_PERF_LADDR_PORT8,  RAW_PERF_LADDR_PORT9
    };
    uint32_t RAW_PERF_FADDR[RAW_PERF_NUM_PORTS_MAX] = { 
        RAW_PERF_FADDR_PORT48, RAW_PERF_FADDR_PORT49, RAW_PERF_FADDR_PORT50, RAW_PERF_FADDR_PORT51,
        RAW_PERF_FADDR_PORT0,  RAW_PERF_FADDR_PORT1,  RAW_PERF_FADDR_PORT2,  RAW_PERF_FADDR_PORT3,
        RAW_PERF_FADDR_PORT4,  RAW_PERF_FADDR_PORT5,  RAW_PERF_FADDR_PORT6,  RAW_PERF_FADDR_PORT7, 
        RAW_PERF_FADDR_PORT8,  RAW_PERF_FADDR_PORT9
    };

    /* local address */
    laddr.sin_family = CVM_SO_AF_INET;
    laddr.sin_len    = sizeof(laddr);
    laddr.sin_port   = 0;

    /* foreign address */
    faddr.sin_family = CVM_SO_AF_INET;
    faddr.sin_len    = sizeof(faddr);
    faddr.sin_port   = 0;

    core_id = cvmx_get_core_num();

    /* initialization */
    memset( (void*)&raw_sockets, 0x0, sizeof(raw_perf_sockets_t) );
    raw_sockets.free_count = RAW_PERF_MAX_SOCKETS;

    raw_ipproto_base = RAW_PERF_IPPROTO_BASE;

#ifdef CVM_COMBINED_APP_STACK
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> CVM_COMBINED_APP_STACK defined. DNI mode test\n\n");
#endif
#ifdef CVM_RAW_TCP_SUPPORT
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> CVM_RAW_TCP_SUPPORT defined\n\n");
#endif
#ifdef CVM_RAW_LOOKUP_V2
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> CVM_RAW_LOOKUP_V2 defined\n\n");
#endif

    printf("%s: core %d, cfg: ports %d, total_sockets %d, sockets_per_port %d, ipproto_base %d\n\n",
            __FUNCTION__, core_id, RAW_PERF_NUM_PORTS, RAW_PERF_MAX_SOCKETS, RAW_PERF_MAX_SOCKETS_PER_PORT, raw_ipproto_base);

    num_sock = 0;
    for (port=0; port<RAW_PERF_NUM_PORTS; ++port)
    {
        for (ff = 0;  ff < RAW_PERF_NUM_FADDR; ff++)  /* 8 faddr per laddr */
        {
            for (n=0; n<RAW_PERF_MAX_SOCKETS_PER_PORT; ++n)
            {
                laddr.sin_addr.s_addr = RAW_PERF_LADDR[port];
                faddr.sin_addr.s_addr = RAW_PERF_FADDR[port] + ff;
                laddr.sin_port = 0;
                faddr.sin_port = 0;

#ifdef CVM_RAW_TCP_SUPPORT
#if 0
                /* TCP filler sockets are the last sockets in the array */
                if (n >= (RAW_PERF_MAX_SOCKETS_PER_PORT-RAW_PERF_TCP_FILLER_SOCKETS_PER_PORT)) 
                {
                    ipproto = CVM_IP_IPPROTO_TCP;
                    laddr.sin_port = (core_id * 1000) + RAW_PERF_TCP_LPORT + n;
                    faddr.sin_port = (core_id * 1000) + RAW_PERF_TCP_FPORT + n;
                } 
                else
                    if ((RAW_PERF_TCP_FILLER_SOCKETS_PER_PORT == 0) && (n == 0))  /* using TCP sockets (not as filler) */
                    {
                        ipproto = CVM_IP_IPPROTO_TCP;
                        laddr.sin_port = (core_id * 1000) + RAW_PERF_TCP_LPORT + n;
                        faddr.sin_port = (core_id * 1000) + RAW_PERF_TCP_FPORT + n;
                    }
                    else
#endif
                    {
                        ipproto = raw_ipproto_base + n + (core_id * RAW_PERF_SOCKETS_PER_PORT);
                        laddr.sin_port = 0;
                        faddr.sin_port = 0;
                    }
#else
                ipproto = raw_ipproto_base + n + (core_id * RAW_PERF_MAX_SOCKETS_PER_PORT);
#endif


#if (defined(RAW_PERF_TEST_ALL_ZEROS) && (!defined(RAW_PERF_TEST_RECV_SEND)))
                if ((num_sock % 100) == 0)
                {
                    laddr.sin_addr.s_addr = 0;
                    faddr.sin_addr.s_addr = 0;
                    laddr.sin_port        = 0;
                    faddr.sin_port        = 0;
                    ipproto               = 0;
                }
#endif

                if (raw_perf_all_zeros_flag == 1)
                {
                    laddr.sin_addr.s_addr = 0;
                    faddr.sin_addr.s_addr = 0;
                    laddr.sin_port        = 0;
                    faddr.sin_port        = 0;
                    ipproto               = 0;
                }

                /* create non-blocking socket */
                raw_sockets.sock[num_sock].fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_RAW, ipproto);
                cvm_so_fcntl(raw_sockets.sock[num_sock].fd, FNONBIO, 1);

#ifdef RAW_PERF_TEST_RECV_SEND
                /* bind */
                retval = cvm_so_bind(raw_sockets.sock[num_sock].fd, (struct cvm_so_sockaddr *)&laddr, sizeof(struct cvm_so_sockaddr));
                if (retval)
                {
                    printf("%s:ERROR so_bind ret %d, core_id %u fd 0x%x laddr 0x%llx::%d, bind FAILED... errno %d\n",
                            __FUNCTION__, retval, core_id, raw_sockets.sock[num_sock].fd, CVM_COMMON_UCAST64(laddr.sin_addr.s_addr), laddr.sin_port, errno);
                }

                /* connect */
                retval = cvm_so_connect(raw_sockets.sock[num_sock].fd, (struct cvm_so_sockaddr*)&faddr, sizeof(struct cvm_so_sockaddr));
                if (retval)
                {
                    printf("%s:ERROR so_connect ret %d, core_id %u fd 0x%x faddr 0x%llx::%d, connect FAILED... errno %d\n",
                            __FUNCTION__, retval, core_id, raw_sockets.sock[num_sock].fd, CVM_COMMON_UCAST64(faddr.sin_addr.s_addr), faddr.sin_port, errno);
                }
#endif

                ++num_sock;
            }  /* ipproto */
        }  /* faddr */
    } /* port */



    /* printf the total number of sockets in the stack-side lookup table */
    cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30);
    if (core_id == 0) cvm_raw_lookup_dump_all(0);
    cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30);

    printf ("%s: core_id %d, Raw sockets non-blocking performance test (non-DNI mode)...\n", __FUNCTION__, core_id);

    /* build the poll list of sockets */
    no_of_fds_to_poll = raw_perf_build_poll_list(&sock_status[0], &raw_sockets, RAW_PERF_MAX_SOCKETS);
    /* raw_perf_poll_list_dump(&sock_status[0], no_of_fds_to_poll, 0); */

    while (1)
    {
        error = cvm_so_poll(no_of_fds_to_poll, &sock_status[0], (struct timeval*)0);
        if (error < 0)
        {
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
                    "%s: cvm_so_poll FAILED errno %d\n", __FUNCTION__, errno);
            return (0);
        }

        if (error == 0)
        {
            /* nothing read - should never happen when the timeout value of poll is 0 */
        }
        else
        {
            raw_perf_process_read(&sock_status[0], no_of_fds_to_poll, &raw_sockets);
        }
    }

    return 0;
}


/**
 * raw_perf_build_poll_list:
 * @status_list - pointer to cvm_so_status structure
 * @sockets     - pointer to raw_perf_sockets_t structure
 * @max         - max number of sockets
 *
 * This routine
 * - builds the list of sockets to be polled
 *
 * Return codes:
 * - fd_count - # sockets to be polled (# sockets in the polling list)
 */
int raw_perf_build_poll_list(cvm_so_status* list, raw_perf_sockets_t* sockets, int max)
{
    int i=0;
    int fd_count = 0;

    for (i=0; i<max; i++)
    {
        if (sockets->sock[i].fd != 0)
        {
            list[fd_count].socket_id = sockets->sock[i].fd;
            list[fd_count].read_ready = 0;
            list[fd_count].write_ready = 0;
            list[fd_count].exception_ready = 0;
            list[fd_count].reserved = i;
            fd_count++;
        }
    }

    return (fd_count);
}


/**
 * raw_perf_process_read:
 * @status_list - pointer to cvm_so_status structure
 * @nfds        - number of sockets in the polling list
 * @sockets     - pointer to raw_perf_sockets_t structure
 *
 * This routine
 * - processes the data, if available
 *
 * Return codes:
 * - 0
 */
int raw_perf_process_read(cvm_so_status* status_list, int nfds, raw_perf_sockets_t* sockets)
{
    int i = 0;

    for (i=0; i<nfds; i++)
    {
        if (status_list[i].read_ready)
        {
            raw_perf_deal_with_data(sockets, status_list[i].reserved);
            status_list[i].read_ready = 0;
            status_list[i].write_ready = 0;
            status_list[i].exception_ready = 0;
        }
    }

    return (0);
}


/**
 * raw_perf_deal_with_data:
 * @sockets     - pointer to raw_perf_sockets_t structure
 * @index       - index for the socket fd
 *
 * This routine
 * - recv the data
 * - send it back to the remote end using sock_raw_send routine
 *
 * Return codes:
 * - 0
 */
int raw_perf_deal_with_data(raw_perf_sockets_t *sockets, int index)
{
    uint8_t in_data[RAW_PERF_DATA_BUFFER_SIZE];
    int error = -1;
    int send_len = 0;
    int recv_len = 0;
    int recv_payload_len = 0;
    int fd = sockets->sock[index].fd;
#ifndef RAW_PERF_TEST_RECV_SEND
    struct cvm_ip_sockaddr_in  faddr_recvfrom;
    int addr_len;
#endif
    /* static uint64_t pkt_num = 0; */

#ifdef RAW_PERF_TEST_RECV_SEND
    recv_len = cvm_so_recv(fd, (void*)in_data, RAW_PERF_DATA_BUFFER_SIZE, 0);
#else
    recv_len = cvm_so_recvfrom(fd, (void*)in_data, RAW_PERF_DATA_BUFFER_SIZE, 0,
                       (struct cvm_so_sockaddr *)&faddr_recvfrom, (cvm_so_socklen_t *)&addr_len);
#endif
    recv_payload_len = recv_len - RAW_PERF_IP_HEADER_LEN;
    if (recv_len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
            "%s: fd 0x%x recv FAILED... errno %d",
            __FUNCTION__, fd, errno);
        return (error);
    }

    if (recv_len == 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO,
           "%s: fd 0x%x connection terminated\n",
           __FUNCTION__, fd);
        return (error);
    }

    /* pkt_num; */
    /* 
    printf(" (%5llu) RECV %d fd 0x%x faddr_recvfrom 0x%llx core_id %lld\n",  
       CAST64(pkt_num), recv_len, fd, CVM_COMMON_UCAST64(faddr_recvfrom.sin_addr.s_addr), CAST64(cvmx_get_core_num()));
    */

do_send_again:
#ifdef CVM_RAW_TCP_SUPPORT

    if (in_data[9] == CVM_IP_IPPROTO_TCP)
    {
        /* Swap the TCP port numbers */
        uint16_t tcp_dport = *((uint16_t *)&in_data[RAW_PERF_IP_HEADER_LEN]);
        uint16_t tcp_sport = *((uint16_t *)&in_data[RAW_PERF_IP_HEADER_LEN+2]);
        *((uint16_t *)&in_data[RAW_PERF_IP_HEADER_LEN])   = tcp_sport;
        *((uint16_t *)&in_data[RAW_PERF_IP_HEADER_LEN+2]) = tcp_dport;
    }
#endif

#ifdef RAW_PERF_TEST_RECV_SEND
    send_len = cvm_so_send(fd, (void*)(&in_data[RAW_PERF_IP_HEADER_LEN]), recv_payload_len, 0);
#else
    send_len = cvm_so_sendto(fd, (void*)(&in_data[RAW_PERF_IP_HEADER_LEN]), recv_payload_len, 0,
                         (struct cvm_so_sockaddr *)&faddr_recvfrom, sizeof(struct cvm_so_sockaddr));
#endif
    if (send_len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
            "%s: fd 0x%x send FAILED... errno %d", __FUNCTION__, fd, errno);
        if (errno == CVM_COMMON_EAGAIN)
        {
            goto do_send_again;
        }
        return (send_len);
    }

    /* 
    printf(" (%5llu) SendTO %d fd 0x%x, faddr_recvfrom 0x%llx, core_id %lld\n",  
         CAST64(pkt_num), send_len, fd, CVM_COMMON_UCAST64(faddr_recvfrom.sin_addr.s_addr), CAST64(cvmx_get_core_num()));
    */

    return 0;
}







/** 
 * raw_perf_poll_list_dump
 * @cvm_so_status     - poll list
 * @no_of_fds_to_poll - number of entries in the poll list
 * @dump_all_flag     - flag to print only the count or all the contents of the entry
 *
 * This routine prints the contents of the poll list
 */
void raw_perf_poll_list_dump(cvm_so_status *list, int no_of_fds_to_poll, int dump_all_flag)
{
    int n;
    int count = 0;

    for (n=0; n<no_of_fds_to_poll; ++n)
    {
        if (dump_all_flag) {
            printf("fd 0x%llx reserved %d read_ready %d write_ready %d exception_ready %lld\n",
                CAST64(list[n].socket_id),
                list[n].reserved,
                list[n].read_ready,
                list[n].write_ready,
                CAST64(list[n].exception_ready));
        }
        ++count;
     }
     printf("%s: core_id %d count %d\n", __FUNCTION__, (int)cvmx_get_core_num(), count);
}

#endif  /* RAW_PERF */



/**
 * sock_raw_bsd_compliance_test:
 *
 * This routine
 * - BSD compliance testing for various error codes
 *
 * Return codes:
 * - 0 
 */
#ifdef SOCK_RAW_BSD_TEST
int sock_raw_bsd_compliance_test()
{
    uint32_t laddr[4]      = {0, SOCK_RAW_LADDR_PORT0, SOCK_RAW_LADDR_PORT1, 0};
    uint8_t  bind_flag[4]  = {0, 1, 1, 1};
    int      i             = 0;
    int      fd1[4];

    uint8_t    in_data[SOCK_RAW_BUF_MAX];
    int        recv_len      = 0;
    cvm_so_socklen_t addr_len    = 0;
    struct cvm_ip_sockaddr_in faddr_recvfrom;


/*
    printf ("**********************************************************************************\n");
    printf ("******************** BSD compliance test cases ***********************************\n");
    printf ("**********************************************************************************\n");
    printf ("A\n");
    printf ("1. no bind, no connect,          send, sendto (faddr 48, 49, 0, 100) \n");
    printf ("2. no bind, connect (faddr 0),   send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("3. no bind, connect (faddr 48),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("4. no bind, connect (faddr 49),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("5. no bind, connect (faddr 100), send, sendto (faddr 48, 49, 0, 100)\n")
    
    printf ("B\n");
    printf ("1. bind 48, no connect,          send, sendto (faddr 48, 49, 0, 100) \n");
    printf ("2. bind 48, connect (faddr 0),   send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("3. bind 48, connect (faddr 48),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("4. bind 48, connect (faddr 49),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("5. bind 48, connect (faddr 100), send, sendto (faddr 48, 49, 0, 100)\n")
    
    printf ("C\n");
    printf ("1. bind 49, no connect,          send, sendto (faddr 48, 49, 0, 100) \n");
    printf ("2. bind 49, connect (faddr 0),   send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("3. bind 49, connect (faddr 48),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("4. bind 49, connect (faddr 49),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("5. bind 49, connect (faddr 100), send, sendto (faddr 48, 49, 0, 100)\n")
    
    printf ("D\n");
    printf ("1. bind 0,  no connect,          send, sendto (faddr 48, 49, 0, 100) \n");
    printf ("2. bind 0,  connect (faddr 0),   send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("3. bind 0,  connect (faddr 48),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("4. bind 0,  connect (faddr 49),  send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("5. bind 0,  connect (faddr 100), send, sendto (faddr 48, 49, 0, 100)\n")
    printf ("**********************************************************************************\n");
    printf ("**********************************************************************************\n");
*/

    /* Foreign address - recvfrom */
    faddr_recvfrom.sin_family      = CVM_SO_AF_INET;
    faddr_recvfrom.sin_addr.s_addr = SOCK_RAW_FADDR_48;
    faddr_recvfrom.sin_port        = 0;
    faddr_recvfrom.sin_len         = sizeof(faddr_recvfrom);

    printf ("\n\nRaw sockets BSD compliance error codes testing...\n");
    printf ("(Note: errno = -99 => last set error code)\n\n");

    for (i = 0; i < 4; i++)
    {
        fd1[i] = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_RAW, CVM_IP_IPPROTO_150);

        printf("\n\n >>>>>>> Send ONE packet ONLY from the remote end >>>>>>>\n\n\n");
        recv_len = cvm_so_recvfrom(fd1[i], (void*)in_data, SOCK_RAW_BUF_MAX, 0,
                       (struct cvm_so_sockaddr *)&faddr_recvfrom, &addr_len);
        if (recv_len < 0) printf("ERROR... recv_len %d errno %d\n", recv_len, errno);

        sock_raw_bsd_send_error_test(fd1[i], 
            bind_flag[i], laddr[i], 
            0, 0,
            SOCK_RAW_FADDR_48, SOCK_RAW_FADDR_49, SOCK_RAW_FADDR_50, SOCK_RAW_FADDR_100);

        sock_raw_bsd_send_error_test(fd1[i], 
            bind_flag[i], laddr[i], 
            1, 0,
            SOCK_RAW_FADDR_48, SOCK_RAW_FADDR_49, SOCK_RAW_FADDR_50, SOCK_RAW_FADDR_100);

        sock_raw_bsd_send_error_test(fd1[i], 
            bind_flag[i], laddr[i], 
            1, SOCK_RAW_FADDR_48,
            SOCK_RAW_FADDR_48, SOCK_RAW_FADDR_49, SOCK_RAW_FADDR_50, SOCK_RAW_FADDR_100);

        sock_raw_bsd_send_error_test(fd1[i], 
            bind_flag[i], laddr[i], 
            1, SOCK_RAW_FADDR_49,
            SOCK_RAW_FADDR_48, SOCK_RAW_FADDR_49, SOCK_RAW_FADDR_50, SOCK_RAW_FADDR_100);

        sock_raw_bsd_send_error_test(fd1[i], 
            bind_flag[i], laddr[i], 
            1, SOCK_RAW_FADDR_100,
            SOCK_RAW_FADDR_48, SOCK_RAW_FADDR_49, SOCK_RAW_FADDR_50, SOCK_RAW_FADDR_100);
    }

    printf("\n\n >>>>>>> End of test >>>>>>>\n\n");

    return 0;
}
#endif



/**
 * sock_raw_bsd_send_error_test:
 *
 * This routine
 * - is used by sock_raw_bsd_compliance_test routine for BSD compliance testing 
 *   for various error codes.
 * - tests scenarios for send and sendto for different combinations of 
 *   - bind_flag
 *   - connect_flag
 *   - foreign address values
 *   - default gateway configuration
 *
 * Return codes:
 * - 0
 */
#ifdef SOCK_RAW_BSD_TEST
void sock_raw_bsd_send_error_test(int fd1, uint8_t bind_flag, uint32_t laddr, uint8_t connect_flag, 
                                  uint32_t faddr, uint32_t sendto_faddr1, uint32_t sendto_faddr2, 
                                  uint32_t sendto_faddr3, uint32_t sendto_faddr4)
{

    uint8_t    out_data[SOCK_RAW_BUF_MAX];
    int        send_len      = 0;
    int        out_len       = 20;
    int        i             = 0;
    int        retval        = 0;
    struct cvm_ip_sockaddr_in faddr_cfg;
    struct cvm_ip_sockaddr_in laddr_cfg;
    int        core_id       = cvmx_get_core_num();
    static int n0 = 1;
    int        n1 = 1;

    memset(out_data, 0, SOCK_RAW_BUF_MAX);
    for (i=0; i<SOCK_RAW_BUF_MAX; ++i)
    {
        *(out_data + i) = (i & 0xFF);
    }

    /* Local address */
    laddr_cfg.sin_family      = CVM_SO_AF_INET;
    laddr_cfg.sin_addr.s_addr = laddr;
    laddr_cfg.sin_port        = 0;
    laddr_cfg.sin_len         = sizeof(laddr_cfg);

    /* Foreign address */
    faddr_cfg.sin_family      = CVM_SO_AF_INET;
    faddr_cfg.sin_addr.s_addr = faddr;
    faddr_cfg.sin_port        = 0;
    faddr_cfg.sin_len         = sizeof(faddr_cfg);

    printf("*********************************************************************************\n");
    if (bind_flag)
    {
        errno = -99;
        retval = cvm_so_bind(fd1, (struct cvm_so_sockaddr *)&laddr_cfg, sizeof(struct cvm_so_sockaddr));
        printf("core_id %u BIND    laddr %s (0x%x), retval %d fd 0x%x ...errno %d\n",
            core_id, inet_ntoa(laddr_cfg.sin_addr), laddr, send_len, fd1, errno);
    }
    else
    {
        printf("core_id %u BIND    OFF\n", core_id);
    }

    if (connect_flag)
    {
        errno = -99;
        retval = cvm_so_connect(fd1, (struct cvm_so_sockaddr *)&faddr_cfg, sizeof(struct cvm_so_sockaddr));
        printf("core_id %u CONNECT faddr %s (0x%x), retval %d fd 0x%x ...errno %d\n",
            core_id, inet_ntoa(faddr_cfg.sin_addr), faddr, send_len, fd1, errno);
    }
    else
    {
        printf("core_id %u CONNECT OFF\n", core_id);
    }

    out_len     = out_len + n0;
    out_data[0] = n0++;


    out_data[1] = n1++;
    printf("---------------------------------------------------------------------------------\n");
    errno = -99;
    send_len = cvm_so_send(fd1, (void*)out_data, out_len, 0);
    printf ("(%2d) core_id %u SEND   send_len %d fd 0x%x, ...errno %d\n",
        n1, core_id, send_len, fd1, errno);

    cvmx_wait(1000*1000*30);

    out_data[1] = n1++;
    printf("---------------------------------------------------------------------------------\n");
    errno = -99;
    faddr_cfg.sin_addr.s_addr = sendto_faddr1;
    send_len = cvm_so_sendto(fd1, (void*)out_data, out_len, 0,
                    (struct cvm_so_sockaddr *)&faddr_cfg, sizeof(struct cvm_so_sockaddr));
    printf ("(%2d) core_id %u SendTO send_len %d fd 0x%x faddr 0x%llx (%s) ...errno %d\n",
        n1, core_id, send_len, fd1, CVM_COMMON_UCAST64(faddr_cfg.sin_addr.s_addr), inet_ntoa(faddr_cfg.sin_addr), errno);


    out_data[1] = n1++;
    printf("---------------------------------------------------------------------------------\n");
    errno = -99;
    faddr_cfg.sin_addr.s_addr = sendto_faddr2;
    send_len = cvm_so_sendto(fd1, (void*)out_data, out_len, 0,
                    (struct cvm_so_sockaddr *)&faddr_cfg, sizeof(struct cvm_so_sockaddr));
    printf ("(%2d) core_id %u SendTO send_len %d fd 0x%x faddr 0x%llx (%s) ...errno %d\n",
        n1, core_id, send_len, fd1, CVM_COMMON_UCAST64(faddr_cfg.sin_addr.s_addr), inet_ntoa(faddr_cfg.sin_addr), errno);


    out_data[1] = n1++;
    printf("---------------------------------------------------------------------------------\n");
    errno = -99;
    faddr_cfg.sin_addr.s_addr = sendto_faddr3;
    send_len = cvm_so_sendto(fd1, (void*)out_data, out_len, 0,
                    (struct cvm_so_sockaddr *)&faddr_cfg, sizeof(struct cvm_so_sockaddr));
    printf ("(%2d) core_id %u SendTO send_len %d fd 0x%x faddr 0x%llx (%s) ...errno %d\n",
        n1, core_id, send_len, fd1, CVM_COMMON_UCAST64(faddr_cfg.sin_addr.s_addr), inet_ntoa(faddr_cfg.sin_addr), errno);


    out_data[1] = n1++;
    printf("---------------------------------------------------------------------------------\n");
    errno = -99;
    faddr_cfg.sin_addr.s_addr = sendto_faddr4;
    send_len = cvm_so_sendto(fd1, (void*)out_data, out_len, 0,
                    (struct cvm_so_sockaddr *)&faddr_cfg, sizeof(struct cvm_so_sockaddr));
    printf ("(%2d) core_id %u SendTO send_len %d fd 0x%x faddr 0x%llx (%s) ...errno %d\n",
        n1, core_id, send_len, fd1, CVM_COMMON_UCAST64(faddr_cfg.sin_addr.s_addr), inet_ntoa(faddr_cfg.sin_addr), errno);

    printf("*********************************************************************************\n\n\n");
}
#endif



/**
 * sock_raw_create_close_test:
 * @cfg - pointer to core configuration structure (sock_raw_core_cfg_t)
 *
 * This routine
 * - tests the functionality of creating sockets and closing them.
 *
 * Return codes:
 * - None
 */






#ifdef INET6
void sock_raw_ip6_hdr_fill(void *ptr, struct cvm_ip6_in6_addr laddr6, struct cvm_ip6_in6_addr faddr6, int ipproto);

int sock_raw_application_v6(void)
{
    int inet6_ixia_flag = 0;
    int inet6_all_zeros_flag = 0;
    int inet6_raw_tcp_flag = 0;
    int inet6_bind_flag = 1;
    int inet6_connect_flag = 1;
    int inet6_multiple_bind_flag = 0;
    int inet6_multiple_connect_flag = 0;
    int bind_max_times = 5;
    int connect_max_times = 5;
    int inet6_iphdr_incl_flag = 0;
    int nnn = 0;

    int fd6 = 0;
    int len = 0;
    int recv_size = 0;
    int error = 0;

    int ipproto = 150;
    int bind_port = 0;
    int connect_port = 200;

    struct cvm_ip6_sockaddr_in6 laddr6;
    struct cvm_ip6_sockaddr_in6 faddr6;
    struct cvm_ip6_sockaddr_in6 addr6;

    int addrlen = 0;
    char buffer[SOCK_RAW_BUF_MAX];
    static uint64_t recv_pkt_num = 0;
    static uint64_t send_pkt_num = 0;
    int core_id = cvmx_get_core_num();

    printf("%s: core_id %d, Starting RAW echo server ...\n", __FUNCTION__, core_id);

    /* create RAW socket */
    if (inet6_all_zeros_flag == 1)
    {
        inet6_bind_flag      = 0;
        inet6_connect_flag   = 0;

        ipproto = 0;
        fd6 = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_RAW, ipproto);
    }
    else if (inet6_raw_tcp_flag == 1)
    {
        ipproto = CVM_IP_IPPROTO_TCP;
        fd6 = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_RAW, ipproto);
    }
    else
    {
        if (inet6_ixia_flag == 1)
            ipproto = 59;
        else
            ipproto = ipproto + cvmx_get_core_num();
        fd6 = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_RAW, ipproto); 
    }

    if (fd6 < 0)
    {
        printf("%s : unable to create v6 raw socket [error = 0x%X]\n", __FUNCTION__, errno);
        return (0);
    }

    if (inet6_iphdr_incl_flag == 1)
    {
        int   retval            = -1;
        int   level             = CVM_SO_SOL_IP;
        int   optname           = CVM_SO_SO_IP_HDRINCL;
        int   optval            = 1;
        cvm_so_socklen_t optlen = sizeof(optval);

        retval = cvm_so_setsockopt (fd6, level, optname, (const void *)&optval, optlen);
        retval = cvm_so_getsockopt (fd6, level, optname, (void *)&optval, (cvm_so_socklen_t *)&optlen);
        printf ("%s: core_id %d fd 0x%x level %d optname %d optval 0x%x optlen %d retval %d\n", __FUNCTION__, core_id, fd6, level, optname, optval, (unsigned int)optlen, retval);
    }

    if (inet6_raw_tcp_flag == 1)
    {
        bind_port    = 100;
    }
    else
    {
        bind_port    = 0;
    }

    /* Initialize bind local address */
    laddr6.sin6_family = CVM_SO_AF_INET6;
    laddr6.sin6_port   = bind_port;
    laddr6.sin6_len    = sizeof(laddr6);
    laddr6.sin6_addr   = cvm_ip6_in6addr_any;

    /* Initialize connect foreign address */
    faddr6.sin6_family = CVM_SO_AF_INET6;
    faddr6.sin6_port   = connect_port;
    faddr6.sin6_len    = sizeof(faddr6);
    faddr6.sin6_addr   = cvm_ip6_in6addr_any;


    /* bind */
    if (inet6_bind_flag == 1)
    {
        if (inet6_multiple_bind_flag == 1) 
        {
            for (nnn=0; nnn<bind_max_times; ++nnn)
            {
                /* bind socket to ANY local address */
                laddr6.sin6_family = CVM_SO_AF_INET6;
                laddr6.sin6_port = bind_port;
                laddr6.sin6_len = sizeof(laddr6);

                if (nnn == 0) 
                {
                    laddr6.sin6_addr = cvm_ip6_in6addr_any;  // recv works
                }
                else
                {
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[0] = 0x2233;
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[1] = 0x4455;
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[2] = 0x6677;
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88a9  + nnn;     // == octeon port1
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[4] = 0x1234;
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[5] = 0x5678;
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[6] = 0xabcd;
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[7] = 0xef32;
                }

                error = cvm_so_bind(fd6, (struct cvm_so_sockaddr*)&laddr6, sizeof(struct cvm_ip6_sockaddr_in6));
                if (error)
                {
                    printf("%s : unable to bind v6 raw socket [error = 0x%X]\n", __FUNCTION__, errno);
                    // return 1;
                }
                printf("%s: IPv6 RAW socket bound to port=%d, addr=%s\n", __FUNCTION__, laddr6.sin6_port, cvm_ip6_ip6_sprintf(&laddr6.sin6_addr));

                cvmx_wait(300 * 1000 * 1000); cvmx_wait(300 * 1000 * 1000);
                if (cvmx_get_core_num() == 0) cvm_raw_lookup_v2_dump_all(1);
                cvmx_wait(300 * 1000 * 1000); cvmx_wait(300 * 1000 * 1000);
            }
        }
        else
        {
            if (inet6_all_zeros_flag == 0)
            {
                /* bind socket to ANY local address */
                laddr6.sin6_family = CVM_SO_AF_INET6;
                laddr6.sin6_len = sizeof(laddr6);
                // laddr6.sin6_addr = cvm_ip6_in6addr_any;

                laddr6.sin6_addr.cvm_ip6_s6_addr16[0] = 0x2233;
                laddr6.sin6_addr.cvm_ip6_s6_addr16[1] = 0x4455;
                laddr6.sin6_addr.cvm_ip6_s6_addr16[2] = 0x6677;
                laddr6.sin6_addr.cvm_ip6_s6_addr16[4] = 0x1234;
                laddr6.sin6_addr.cvm_ip6_s6_addr16[5] = 0x5678;
                laddr6.sin6_addr.cvm_ip6_s6_addr16[6] = 0xabcd;
                laddr6.sin6_addr.cvm_ip6_s6_addr16[7] = 0xef32;

                if (inet6_raw_tcp_flag == 1)
                {
                    if (core_id == 0)
                    {
                        laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88a9;     // == octeon port1
                        laddr6.sin6_port = bind_port;
                    }
                    else if (core_id == 1)
                    {
                        laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88aa;     // == octeon port2
                        laddr6.sin6_port = bind_port;
                    }
                    else if (core_id == 2)
                    {
                        laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88ab;     // == octeon port3
                        laddr6.sin6_port = bind_port;
                    }
                    else if (core_id == 3)
                    {
                        laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88ac;     // == octeon port4
                        laddr6.sin6_port = bind_port;
                    }
                    else
                    {
                        laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88a9;     // == octeon port1
                        laddr6.sin6_port = bind_port + cvmx_get_core_num();
                    }
                }
                else
                {
                    laddr6.sin6_port = 0;
                    laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88aa  + nnn;     // == octeon port2
                }
            }

            error = cvm_so_bind(fd6, (struct cvm_so_sockaddr*)&laddr6, sizeof(struct cvm_ip6_sockaddr_in6));
            if (error)
            {
                printf("%s : unable to bind v6 raw socket [error = 0x%X]\n", __FUNCTION__, errno);
                // return 1;
            }
        }
    }

    /* connect */
    if (inet6_connect_flag == 1)
    {
        if (inet6_multiple_connect_flag == 1) 
        {
            for (nnn=0; nnn<connect_max_times; ++nnn)
            {
                faddr6.sin6_family = CVM_SO_AF_INET6;
                faddr6.sin6_port = connect_port;
                faddr6.sin6_len = sizeof(faddr6);

                if (nnn == 0)
                {
                    faddr6.sin6_addr = cvm_ip6_in6addr_any;  // recv works
                }
                else
                {
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[0] = 0x2233;
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[1] = 0x4455;
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[2] = 0x6677;
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88a9 + nnn;     // == octeon port1
                    // faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88aa;     // == octeon port2
                    // faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88ab;     // == octeon port3
                    // faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88ac;     // == octeon port4
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[4] = 0x1234;
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[5] = 0x5678;
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[6] = 0xabcd;
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[7] = 0xef33;
                }

                    error = cvm_so_connect(fd6, (struct cvm_so_sockaddr*)&faddr6, sizeof(struct cvm_ip6_sockaddr_in6));
                    if (error)
                    {
                        printf("%s : unable to connect v6 raw socket [error = 0x%X]\n", __FUNCTION__, errno);
                        // return 1;
                    }
                    printf("%s: IPv6 RAW socket connected port=%d, addr=%s\n", __FUNCTION__, faddr6.sin6_port, cvm_ip6_ip6_sprintf(&faddr6.sin6_addr));

                    cvmx_wait(300 * 1000 * 1000); cvmx_wait(300 * 1000 * 1000);
                    if (cvmx_get_core_num() == 0) cvm_raw_lookup_v2_dump_all(1);
                    cvmx_wait(300 * 1000 * 1000); cvmx_wait(300 * 1000 * 1000);
                }
        }
        else 
        {
            if (inet6_all_zeros_flag == 0)
            {
                faddr6.sin6_family = CVM_SO_AF_INET6;
                faddr6.sin6_port = connect_port + cvmx_get_core_num();
                faddr6.sin6_len = sizeof(faddr6);

                faddr6.sin6_addr.cvm_ip6_s6_addr16[0] = 0x2233;
                faddr6.sin6_addr.cvm_ip6_s6_addr16[1] = 0x4455;
                faddr6.sin6_addr.cvm_ip6_s6_addr16[2] = 0x6677;
                faddr6.sin6_addr.cvm_ip6_s6_addr16[4] = 0x1234;
                faddr6.sin6_addr.cvm_ip6_s6_addr16[5] = 0x5678;
                faddr6.sin6_addr.cvm_ip6_s6_addr16[6] = 0xabcd;
                faddr6.sin6_addr.cvm_ip6_s6_addr16[7] = 0xef33;

                if (inet6_raw_tcp_flag == 1)
                {
                    faddr6.sin6_port = connect_port;

                    if (core_id == 0)
                    {
                        faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88a9;     // == octeon port1
                    }
                    else if (core_id == 1)
                    {
                        faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88aa;     // == octeon port2
                    }
                    else if (core_id == 2)
                    {
                        faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88ab;     // == octeon port3
                    }
                    else if (core_id == 3)
                    {
                        faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88ac;     // == octeon port4
                    }
                    else
                    {
                        faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88a9;     // == octeon port1
                        faddr6.sin6_port = connect_port + cvmx_get_core_num();
                    }
                }
                else
                {
                    faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = 0x88aa;     // == octeon port2
                    faddr6.sin6_port = connect_port + core_id;
                }
            }

            error = cvm_so_connect(fd6, (struct cvm_so_sockaddr*)&faddr6, sizeof(struct cvm_ip6_sockaddr_in6));
            if (error)
            {
                printf("%s : unable to connect v6 raw socket [error = 0x%X]\n", __FUNCTION__, errno);
                // return 1;
            }
        }
    }

    cvmx_wait(300 * 1000 * 1000);
    if (cvmx_get_core_num() == 0) cvm_raw_lookup_dump_all(1);
    cvmx_wait(300 * 1000 * 1000);

    recv_size = SOCK_RAW_BUF_MAX;

    /* now do the data send/recv */
    while(1)
    {
        /* do a recvfrom*/
        if (inet6_bind_flag == 1)
        {
            len = cvm_so_recv(fd6, (void*)buffer, recv_size, 0);
            if (len == -1)
            {
                printf("%s : recv on RAW fd %d failed (error = 0x%X)\n", __FUNCTION__, fd6, errno);
                // break;
            }
            ++recv_pkt_num;
            // printf(" (%5llu) RECV     %d fd 0x%x faddr_connect %s fport %d, core_id %lld\n",  CAST64(recv_pkt_num), len, fd6, cvm_ip6_ip6_sprintf(&faddr6.sin6_addr), faddr6.sin6_port, CAST64(cvmx_get_core_num()));
        }
        else
        {
            len = cvm_so_recvfrom(fd6, (void*)buffer, recv_size, 0, (struct cvm_so_sockaddr*)&addr6, (cvm_so_socklen_t*)&addrlen);
            if (len == -1)
            {
                printf("%s : recvFROM on RAW fd %d failed (error = 0x%X)\n", __FUNCTION__, fd6, errno);
                // break;
            }
            ++recv_pkt_num;
            // printf(" (%5llu) RecvFROM %d fd 0x%x faddr_recvfrom %s fport %d, core_id %lld\n",  CAST64(recv_pkt_num), len, fd6, cvm_ip6_ip6_sprintf(&addr6.sin6_addr), addr6.sin6_port, CAST64(cvmx_get_core_num()));
        }


        if (inet6_connect_flag == 1)
        {
            if (inet6_iphdr_incl_flag == 1)
            {
                if (inet6_bind_flag == 0)
                {
                    sock_raw_ip6_hdr_fill((void *)&buffer[0], cvm_ip6_in6addr_any, *((struct cvm_ip6_in6_addr *)&faddr6.sin6_addr), ipproto);
                }
                else
                {
                    sock_raw_ip6_hdr_fill((void *)&buffer[0], *((struct cvm_ip6_in6_addr *)&laddr6.sin6_addr), *((struct cvm_ip6_in6_addr *)&faddr6.sin6_addr), ipproto);
                }
                error = cvm_so_send(fd6, (void*)&buffer[0], len, 0);
            }
            else
            {
                error = cvm_so_send(fd6, (void*)&buffer[40], len-40, 0);
            }
            if (error == -1)
            {
                // printf("%s : send on RAW fd %d failed (error = 0x%X)\n", __FUNCTION__, fd6, errno); 
                // break;
            }
            ++send_pkt_num;

            // printf(" (%5llu) SEND     %d fd 0x%x faddr_connect %s fport %d, core_id %lld\n",  CAST64(send_pkt_num), len-40, fd6, cvm_ip6_ip6_sprintf(&faddr6.sin6_addr), faddr6.sin6_port, CAST64(cvmx_get_core_num()));
        }
        else 
        {
            if (inet6_iphdr_incl_flag == 1)
            {
                if (inet6_bind_flag == 0)
                {
                    sock_raw_ip6_hdr_fill((void *)&buffer[0], cvm_ip6_in6addr_any, *((struct cvm_ip6_in6_addr *)&addr6.sin6_addr), ipproto);
                }
                else
                {
                    sock_raw_ip6_hdr_fill((void *)&buffer[0], *((struct cvm_ip6_in6_addr *)&laddr6.sin6_addr), *((struct cvm_ip6_in6_addr *)&addr6.sin6_addr), ipproto);
                }

                error = cvm_so_sendto(fd6, (void*)&buffer[0], len, 0, (struct cvm_so_sockaddr*)&addr6, addrlen);
            }
            else
            {
                error = cvm_so_sendto(fd6, (void*)&buffer[40], len-40, 0, (struct cvm_so_sockaddr*)&addr6, addrlen);
            }
            if (error == -1)
            {
                // printf("%s : sendTO on RAW fd %d failed (error = 0x%X)\n", __FUNCTION__, fd6, errno); 
                // break;
            }
            ++send_pkt_num;
            // printf(" (%5llu) SendTO   %d fd 0x%x faddr_recvfrom %s fport %d, core_id %lld\n",  CAST64(send_pkt_num), len-40, fd6, cvm_ip6_ip6_sprintf(&addr6.sin6_addr), addr6.sin6_port, CAST64(cvmx_get_core_num()));
        }
    }


    cvm_so_close(fd6);

    return (0);
}


void sock_raw_ip6_hdr_fill(void *ptr, struct cvm_ip6_in6_addr laddr6, struct cvm_ip6_in6_addr faddr6, int ipproto)
{
    cvm_ip6_ip6_t *ip6 = (cvm_ip6_ip6_t *)ptr;

    /* cvm_ip6_in6_addr_t laddr6_to_be_used = CVM_IP6_IN6ADDR_ANY_INIT; */
#if 0
    ip6->ip6_ctlun.ip6_un1.ip6_un1_flow = CVM_IP_IP_FLOWLABEL;
    ip6->ip6_ctlun.ip6_un1.ip6_un1_plen = payload_len;
    ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt  = ipproto;
    ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = CVM_IP_IP_HOP_LIMIT;
    ip6->ip6_ctlun.ip6_un2_vfc          = CVM_IP6_IPV6_VERSION;
#endif

    CVM_RAW_MEMCPY(ip6->ip6_src, laddr6, sizeof(struct cvm_ip6_in6_addr));
    CVM_RAW_MEMCPY(ip6->ip6_dst, faddr6, sizeof(struct cvm_ip6_in6_addr));

    /* printf("%s: sa %s, da %s\n", __FUNCTION__, cvm_ip6_ip6_sprintf(&ip6->ip6_src), cvm_ip6_ip6_sprintf(&ip6->ip6_dst)); */
}
#endif


#ifdef INET6
/* Foreign address - remote machine */
#define RAW6_PERF_FADDR6_PORT0      0
#define RAW6_PERF_FADDR6_PORT1      0
#define RAW6_PERF_FADDR6_PORT2      0
#define RAW6_PERF_FADDR6_PORT3      0
#define RAW6_PERF_FADDR6_PORT4      0
#define RAW6_PERF_FADDR6_PORT5      0
#define RAW6_PERF_FADDR6_PORT6      0
#define RAW6_PERF_FADDR6_PORT7      0
#define RAW6_PERF_FADDR6_PORT8      0
#define RAW6_PERF_FADDR6_PORT9      0
#define RAW6_PERF_FADDR6_PORT48     0x88a9
#define RAW6_PERF_FADDR6_PORT49     0x88aa
#define RAW6_PERF_FADDR6_PORT50     0x88ab
#define RAW6_PERF_FADDR6_PORT51     0x88ac

/* Local address */
#define RAW6_PERF_LADDR6_PORT0      0
#define RAW6_PERF_LADDR6_PORT1      0
#define RAW6_PERF_LADDR6_PORT2      0
#define RAW6_PERF_LADDR6_PORT3      0
#define RAW6_PERF_LADDR6_PORT4      0
#define RAW6_PERF_LADDR6_PORT5      0
#define RAW6_PERF_LADDR6_PORT6      0
#define RAW6_PERF_LADDR6_PORT7      0
#define RAW6_PERF_LADDR6_PORT8      0
#define RAW6_PERF_LADDR6_PORT9      0
#define RAW6_PERF_LADDR6_PORT48     0x88a9
#define RAW6_PERF_LADDR6_PORT49     0x88aa
#define RAW6_PERF_LADDR6_PORT50     0x88ab
#define RAW6_PERF_LADDR6_PORT51     0x88ac

#define RAW6_PERF_NUM_APP_CORES_MAX    15
#define RAW6_PERF_NUM_APP_CORES        NUM_APP_PROCESSORS  /* NOTE: Make sure this value is same as # App Cores used */
#define RAW6_PERF_NUM_PORTS_MAX        14  
#define RAW6_PERF_NUM_PORTS            4    /* RAW6_PERF_NUM_PORTS_MAX */

#define RAW6_PERF_SOCKETS_PER_CORE              (RAW6_PERF_NUM_PORTS * 2)
#define RAW6_PERF_SOCKETS_PER_PORT              ((RAW6_PERF_SOCKETS_PER_CORE * RAW6_PERF_NUM_APP_CORES)/RAW6_PERF_NUM_PORTS)
#define RAW6_PERF_TOTAL_FADDR_PER_PORT          (RAW6_PERF_SOCKETS_PER_PORT)
/* #define RAW6_PERF_NUM_FADDR_PER_PORT_PER_CORE   (RAW6_PERF_TOTAL_FADDR_PER_PORT/RAW6_PERF_NUM_APP_CORES) */
#define RAW6_PERF_TOTAL_SOCKETS                 (RAW6_PERF_SOCKETS_PER_CORE * RAW6_PERF_NUM_APP_CORES)
#define RAW6_PERF_MAX_SOCKETS                   (RAW6_PERF_NUM_APP_CORES * RAW6_PERF_NUM_PORTS * RAW6_PERF_SOCKETS_PER_CORE)

#define RAW6_PERF_IPPROTO_BASE         59    /* Ixia  */
#define RAW6_PERF_DATA_BUFFER_SIZE     65535
#define RAW6_PERF_IP6_HEADER_LEN       40

#define RAW6_PERF_TEST_RECV_SEND

typedef struct _raw6_perf_socket_info
{
   int                       fd;
   struct cvm_ip_sockaddr_in addr;
   int                       addrlen;
   int                       mode;
} raw6_perf_socket_info_t;


typedef struct _raw6_perf_sockets
{
    int free_count;
    raw6_perf_socket_info_t sock[RAW6_PERF_MAX_SOCKETS];
} raw6_perf_sockets_t;

int  raw6_perf_build_poll_list(cvm_so_status* list, raw6_perf_sockets_t* sockets, int max);
int  raw6_perf_process_read(cvm_so_status* status_list, int nfds, raw6_perf_sockets_t* sockets);
int  raw6_perf_deal_with_data(raw6_perf_sockets_t* sockets, int index);
void raw6_perf_poll_list_dump(cvm_so_status *list, int no_of_fds_to_poll, int dump_all_flag);


/* Presently supports IPv6 sockets only */
int raw6_perf_application ()
{
    int raw6_perf_all_zeros_flag = 0;  // RAW6_PERF_TEST_RECV_SEND must be undefined for raw6_perf_all_zeros_flag = 1
    int ixia_flag    = 1;
    int bind_flag    = 0;
    int connect_flag = 0;
    int core_id = cvmx_get_core_num();
    int no_of_fds_to_poll = 0;
    int error;
    int fport = 200;
    int lport = 0;
    int ff = 0;
    int num_sock = 0;
    int port = 0;
    int ipproto = 0;
    cvm_so_status sock_status[RAW6_PERF_MAX_SOCKETS];
    raw6_perf_sockets_t raw_sockets;
    int faddr6_min = 0;
    int faddr6_max = 0;
    int faddr6_base = 0;

    struct cvm_ip6_sockaddr_in6 laddr6;
    struct cvm_ip6_sockaddr_in6 faddr6;

    uint32_t RAW6_PERF_LADDR6[RAW6_PERF_NUM_PORTS_MAX] = {
        RAW6_PERF_LADDR6_PORT48, RAW6_PERF_LADDR6_PORT49, RAW6_PERF_LADDR6_PORT50, RAW6_PERF_LADDR6_PORT51,
        RAW6_PERF_LADDR6_PORT0,  RAW6_PERF_LADDR6_PORT1,  RAW6_PERF_LADDR6_PORT2,  RAW6_PERF_LADDR6_PORT3,        
        RAW6_PERF_LADDR6_PORT4,  RAW6_PERF_LADDR6_PORT5,  RAW6_PERF_LADDR6_PORT6,  RAW6_PERF_LADDR6_PORT7,
        RAW6_PERF_LADDR6_PORT8,  RAW6_PERF_LADDR6_PORT9
    };

    uint32_t RAW6_PERF_FADDR6[RAW6_PERF_NUM_PORTS_MAX] = {
        RAW6_PERF_FADDR6_PORT48, RAW6_PERF_FADDR6_PORT49, RAW6_PERF_FADDR6_PORT50, RAW6_PERF_FADDR6_PORT51,
        RAW6_PERF_FADDR6_PORT0,  RAW6_PERF_FADDR6_PORT1,  RAW6_PERF_FADDR6_PORT2,  RAW6_PERF_FADDR6_PORT3,        
        RAW6_PERF_FADDR6_PORT4,  RAW6_PERF_FADDR6_PORT5,  RAW6_PERF_FADDR6_PORT6,  RAW6_PERF_FADDR6_PORT7,
        RAW6_PERF_FADDR6_PORT8,  RAW6_PERF_FADDR6_PORT9
    };

    int RAW6_PERF_NUM_FADDR_PER_PORT_PER_CORE = 0;
    int raw6_perf_num_app_cores               = RAW6_PERF_NUM_APP_CORES;
    if (RAW6_PERF_NUM_APP_CORES == 0)
    {
        printf("ERROR: For non-DNI mode, the number of application cores must be greater than zero. Exiting...\n");
        exit(-1);
    }
    RAW6_PERF_NUM_FADDR_PER_PORT_PER_CORE = (RAW6_PERF_TOTAL_FADDR_PER_PORT/raw6_perf_num_app_cores);

#ifdef CVM_COMBINED_APP_STACK
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> CVM_COMBINED_APP_STACK defined. DNI mode test\n\n");
#endif
#ifdef CVM_RAW_TCP_SUPPORT
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> CVM_RAW_TCP_SUPPORT defined\n\n");
#endif
#ifdef CVM_RAW_LOOKUP_V2
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> CVM_RAW_LOOKUP_V2 defined\n\n");
#endif

#ifdef RAW6_PERF_TEST_RECV_SEND
    bind_flag    = 1;
    connect_flag = 1;
    raw6_perf_all_zeros_flag = 0;
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> RAW6_PERF_TEST_RECV_SEND defined, bind_flag %d, connect_flag %d, all_zeros_flag %d\n\n", bind_flag, connect_flag, raw6_perf_all_zeros_flag);
#else
    bind_flag    = 0;
    connect_flag = 0;
    if (core_id == 0) printf ("\n\n>>>>>>>>>>>> RAW6_PERF_TEST_RECV_SEND NOT defined, bind_flag %d, connect_flag %d, all_zeros_flag %d\n\n", bind_flag, connect_flag, raw6_perf_all_zeros_flag);
#endif

    /* local address */
    {
        laddr6.sin6_family = CVM_SO_AF_INET6;
        laddr6.sin6_port   = lport;
        laddr6.sin6_len    = sizeof(laddr6);
        // laddr6.sin6_addr   = cvm_ip6_in6addr_any;

        laddr6.sin6_addr.cvm_ip6_s6_addr16[0] = 0x2233;
        laddr6.sin6_addr.cvm_ip6_s6_addr16[1] = 0x4455;
        laddr6.sin6_addr.cvm_ip6_s6_addr16[2] = 0x6677;
        laddr6.sin6_addr.cvm_ip6_s6_addr16[4] = 0x1234;
        laddr6.sin6_addr.cvm_ip6_s6_addr16[5] = 0x5678;
        laddr6.sin6_addr.cvm_ip6_s6_addr16[6] = 0xabcd;
        laddr6.sin6_addr.cvm_ip6_s6_addr16[7] = 0xef32;

        laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = RAW6_PERF_LADDR6_PORT48;   // 0x88a9;
    }


    /* foreign address */
    {
        faddr6.sin6_family = CVM_SO_AF_INET6;
        faddr6.sin6_port   = fport;
        faddr6.sin6_len    = sizeof(faddr6);

        faddr6.sin6_addr.cvm_ip6_s6_addr16[0] = 0x2233;
        faddr6.sin6_addr.cvm_ip6_s6_addr16[1] = 0x4455;
        faddr6.sin6_addr.cvm_ip6_s6_addr16[2] = 0x6677;         
        faddr6.sin6_addr.cvm_ip6_s6_addr16[4] = 0x1234;
        faddr6.sin6_addr.cvm_ip6_s6_addr16[5] = 0x5678;
        faddr6.sin6_addr.cvm_ip6_s6_addr16[6] = 0xabcd;
        faddr6.sin6_addr.cvm_ip6_s6_addr16[7] = 0xef33;

        faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = RAW6_PERF_FADDR6_PORT48;   // 0x88a9;
    }


    /* initialization */
    memset( (void*)&raw_sockets, 0x0, sizeof(raw6_perf_sockets_t) );

    raw_sockets.free_count = RAW6_PERF_MAX_SOCKETS;
    ipproto                = RAW6_PERF_IPPROTO_BASE;
    num_sock               = 0;

    faddr6_min = core_id * RAW6_PERF_NUM_FADDR_PER_PORT_PER_CORE;
    faddr6_max = faddr6_min + RAW6_PERF_NUM_FADDR_PER_PORT_PER_CORE;
    faddr6_base = faddr6.sin6_addr.cvm_ip6_s6_addr16[7];

    printf("\n>>>>>>>>>>>>>> core_id %d, sockets_per_core %d, faddr6_min %d, faddr6_max %d, num_ports %d\n\n", core_id, RAW6_PERF_SOCKETS_PER_CORE, faddr6_min, faddr6_max, RAW6_PERF_NUM_PORTS);

    for (port = 0; port < RAW6_PERF_NUM_PORTS; ++port)
    {
        for (ff = faddr6_min;  ff < faddr6_max; ff++)
        {
            laddr6.sin6_addr.cvm_ip6_s6_addr16[3] = RAW6_PERF_LADDR6[port];
            laddr6.sin6_port = 0;

            faddr6.sin6_addr.cvm_ip6_s6_addr16[3] = RAW6_PERF_FADDR6[port];
            faddr6.sin6_addr.cvm_ip6_s6_addr16[7] = faddr6_base + ff;
            faddr6.sin6_port = fport;

            // printf("core_id %d :::laddr %s faddr %s ipproto %d\n", core_id, cvm_ip6_ip6_sprintf(&laddr6.sin6_addr), cvm_ip6_ip6_sprintf(&faddr6.sin6_addr), ipproto);

            if (raw6_perf_all_zeros_flag == 1)
            {
                laddr6.sin6_addr = cvm_ip6_in6addr_any;
                faddr6.sin6_addr = cvm_ip6_in6addr_any;
                laddr6.sin6_port = 0;
                faddr6.sin6_port = fport;
                ipproto          = 0;
            }

            if(ixia_flag == 1)
                ipproto = 59;

            /* create non-blocking socket */
            raw_sockets.sock[num_sock].fd = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_RAW, ipproto);
            cvm_so_fcntl(raw_sockets.sock[num_sock].fd, FNONBIO, 1);

            if (bind_flag == 1)
            {
                error = cvm_so_bind(raw_sockets.sock[num_sock].fd, (struct cvm_so_sockaddr*)&laddr6, sizeof(struct cvm_ip6_sockaddr_in6));
                if (error)
                    printf("%s : unable to bind v6 raw socket [error = 0x%X]\n", __FUNCTION__, errno);
            }

            if (connect_flag == 1)
            {
                error = cvm_so_connect(raw_sockets.sock[num_sock].fd, (struct cvm_so_sockaddr*)&faddr6, sizeof(struct cvm_ip6_sockaddr_in6));
                if (error)
                    printf("%s : unable to connect v6 raw socket [error = 0x%X]\n", __FUNCTION__, errno);

            }

            ++num_sock;
        }  /* faddr6 */
    } /* port */


    /* printf the total number of sockets in the stack-side lookup table */
    cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30);
    if (core_id == 0) cvm_raw_lookup_dump_all(0);
    if ((RAW6_PERF_NUM_APP_CORES-1) != 0)
    {
        if (core_id == (RAW6_PERF_NUM_APP_CORES-1)) cvm_raw_lookup_dump_all(0);
    }
    cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30); cvmx_wait(1000*1000*30);

    printf ("%s: core_id %d, Raw sockets (v6) non-blocking performance test (non-DNI mode)...\n", __FUNCTION__, core_id);


    /* build the poll list of sockets */
    no_of_fds_to_poll = raw6_perf_build_poll_list(&sock_status[0], &raw_sockets, RAW6_PERF_MAX_SOCKETS);
    // raw6_perf_poll_list_dump(&sock_status[0], no_of_fds_to_poll, 0);

    while (1)
    {
        errno = -99;
        error = cvm_so_poll(no_of_fds_to_poll, &sock_status[0], (struct timeval*)0);
        if (error < 0)
        {
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "%s: cvm_so_poll FAILED errno %d\n", __FUNCTION__, errno);
            return (0);
        }

        if (error == 0)
        {
            /* nothing read - should never happen when the timeout value of poll is 0 */
        }
        else
        {
            raw6_perf_process_read(&sock_status[0], no_of_fds_to_poll, &raw_sockets);
        }
    }

    return 0;
}


int raw6_perf_build_poll_list(cvm_so_status* list, raw6_perf_sockets_t* sockets, int max)
{
    int i=0;
    int fd_count = 0;

    for (i=0; i<max; i++)
    {
        if (sockets->sock[i].fd != 0)
        {
            list[fd_count].socket_id = sockets->sock[i].fd;
            list[fd_count].read_ready = 0;
            list[fd_count].write_ready = 0;
            list[fd_count].exception_ready = 0;
            list[fd_count].reserved = i;
            fd_count++;
        }
    }

    return (fd_count);
}



int raw6_perf_process_read(cvm_so_status* status_list, int nfds, raw6_perf_sockets_t* sockets)
{
    int i = 0;

    for (i=0; i<nfds; i++)
    {
        if (status_list[i].read_ready)
        {
            raw6_perf_deal_with_data(sockets, status_list[i].reserved);
            status_list[i].read_ready = 0;
            status_list[i].write_ready = 0;
            status_list[i].exception_ready = 0;
        }
    }

    return (0);
}


int raw6_perf_deal_with_data(raw6_perf_sockets_t *sockets, int index)
{
    uint8_t in_data[RAW6_PERF_DATA_BUFFER_SIZE];
    int error = -1;
    int send_len = 0;
    int recv_len = 0;
    int recv_payload_len = 0;
    int fd = sockets->sock[index].fd;
#ifndef RAW6_PERF_TEST_RECV_SEND
    struct cvm_ip6_sockaddr_in6  faddr6_recvfrom;
    int addr_len;
#endif
    /* static uint64_t pkt_num = 0; */

#ifdef RAW6_PERF_TEST_RECV_SEND
    recv_len = cvm_so_recv(fd, (void*)in_data, RAW6_PERF_DATA_BUFFER_SIZE, 0);
#else
    recv_len = cvm_so_recvfrom(fd, (void*)in_data, RAW6_PERF_DATA_BUFFER_SIZE, 0,
                       (struct cvm_so_sockaddr *)&faddr6_recvfrom, (cvm_so_socklen_t *)&addr_len);
#endif
    recv_payload_len = recv_len - RAW6_PERF_IP6_HEADER_LEN;
    if (recv_len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
            "%s: fd 0x%x recv FAILED... errno %d",
            __FUNCTION__, fd, errno);
        return (error);
    }

    if (recv_len == 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO,
           "%s: fd 0x%x connection terminated\n",
           __FUNCTION__, fd);
        return (error);
    }

    /* ++pkt_num; */
    /*
    printf(" (%5llu) RECV %d fd 0x%x faddr6_recvfrom 0x%llx core_id %lld\n",
       CAST64(pkt_num), recv_len, fd, cvm_ip6_ip6_sprintf(&faddr6_recvfrom.sin6_addr), CAST64(cvmx_get_core_num()));
    */





do_send_again:
#ifdef RAW6_PERF_TEST_RECV_SEND
    send_len = cvm_so_send(fd, (void*)(&in_data[RAW6_PERF_IP6_HEADER_LEN]), recv_payload_len, 0);
#else
    send_len = cvm_so_sendto(fd, (void*)(&in_data[RAW6_PERF_IP6_HEADER_LEN]), recv_payload_len, 0,
                         (struct cvm_so_sockaddr *)&faddr6_recvfrom, sizeof(struct cvm_so_sockaddr));
#endif
    if (send_len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR,
            "%s: fd 0x%x send FAILED... errno %d", __FUNCTION__, fd, errno);
        if (errno == CVM_COMMON_EAGAIN)
        {
            goto do_send_again;
        }
        return (send_len);
    }

    /*
    printf(" (%5llu) SendTO %d fd 0x%x, faddr6_recvfrom 0x%llx, core_id %lld\n",
         CAST64(pkt_num), send_len, fd, cvm_ip6_ip6_sprintf(&faddr6_recvfrom.sin6_addr), CAST64(cvmx_get_core_num()));
    */

    return 0;
}







void raw6_perf_poll_list_dump(cvm_so_status *list, int no_of_fds_to_poll, int dump_all_flag)
{
    int n;
    int count = 0;

    for (n=0; n<no_of_fds_to_poll; ++n)
    {
        if (dump_all_flag) {
            printf("fd 0x%llx reserved %d read_ready %d write_ready %d exception_ready %lld\n",
                CAST64(list[n].socket_id),
                list[n].reserved,
                list[n].read_ready,
                list[n].write_ready,
                CAST64(list[n].exception_ready));
        }
        ++count;
     }
     printf("%s: core_id %d count %d\n", __FUNCTION__, (int)cvmx_get_core_num(), count);
}
#endif

