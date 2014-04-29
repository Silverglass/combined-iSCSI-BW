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
#include <assert.h>
#include "cvm-common-errno.h"

#include "cvmx-config.h"
#include "global-config.h"

#if defined(CVM_COMBINED_APP_STACK)

#if defined (DNI_APP_CLIENT)

#include "cvmx.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-spinlock.h"
#include "cvmx-malloc.h"

#include "cvm-common-wqe.h"
#include "cvm-common-defs.h"
#include "cvm-common-misc.h"
#include "cvm-common-fpa.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-if-var.h"

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#include "cvm-ip6-var.h"
#endif

#include "socket.h"
#include "socketvar.h"
#include "cvm-tcp-var.h"
#include "cvm-socket.h"
#include "cvm-socket-cb.h"

#include "inic.h"


/*
 * defines
 */
#define DATA_LEN                 512         /* 512 bytes of data */
#define MAX_LOOP_COUNT          1000         /* no. of connections */

#define REMOTE_IP_ADDR    0xC0A83096         /* 192.168.48.150 */
#define REMOTE_PORT             1500

/*
 * SHARED globals
 */
CVMX_SHARED int loop_count = 0;
CVMX_SHARED uint16_t current_rport = REMOTE_PORT;

/*
 * per core globals
 */
char out_data[DATA_LEN];
char in_data[DATA_LEN+64];

/* 
 * callback prototypes 
 */
int clnt_init_global (void);
int clnt_init_local (void);
int clnt_main_global (void);
int clnt_main_local (void);
int clnt_timeout_handler (void);
int clnt_notification (uint32_t fd, void* context, uint32_t event_flags);
int clnt_exit_local (void);
int clnt_exit_global (void);

int clnt_do_single_connect(void);



/*
 * register callbacks
 */
int cvm_register_dni_callback (void)
{
    int error = 1;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

    do 
    {
        if ((error = cvm_so_register_function ((void *) clnt_init_global, CVM_SO_FNPTR_INIT_GLOBAL, 0)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_init_global failed\n");
            break;
        }

        if ((error = cvm_so_register_function ((void *) clnt_init_local, CVM_SO_FNPTR_INIT_LOCAL, 0)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_init_local failed\n");
            break;
        }

        if ((error = cvm_so_register_function ((void *) clnt_main_global, CVM_SO_FNPTR_MAIN_GLOBAL, 0)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_main_global failed\n");
            break;
        }

        if ((error = cvm_so_register_function ((void *) clnt_main_local, CVM_SO_FNPTR_MAIN_LOCAL, 0)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_main_local failed\n");
            break;
        }

        if ((error = cvm_so_register_function ((void *) clnt_timeout_handler, CVM_SO_FNPTR_TIMEOUT_HANDLER, 0xfffffff)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_timeout_handler failed\n");
            break;
        }

        if ((error = cvm_so_register_function ((void *) clnt_notification, CVM_SO_FNPTR_NOTIFICATION, 0)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_notification failed\n");
            break;
        }

        if ((error = cvm_so_register_function ((void *) clnt_exit_global, CVM_SO_FNPTR_EXIT_GLOBAL, 0)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_exit_global failed\n");
            break;
        }

        if ((error = cvm_so_register_function ((void *) clnt_exit_local, CVM_SO_FNPTR_EXIT_LOCAL, 0)) != 0) 
        {
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering clnt_exit_local failed\n");
            break;
        }

	error = 0;

    } while (0);

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

    return (error);
}



/*
 * global init
 */
int clnt_init_global (void)
{
    int error = 0;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

    return (error);
}


/*
 * local init (per core)
 */
int clnt_init_local (void) 
{
    int error = 0;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

    return (error);
}


/*
 * main global
 */
int clnt_main_global (void)
{
    int error = 0;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

    printf("Starting DNI client application test for %d iterations\n", MAX_LOOP_COUNT);
    printf("Remote IP address = 0x%X, Remotr port = %d\n", REMOTE_IP_ADDR, REMOTE_PORT);

    /* initiate the first connect */
    if (clnt_do_single_connect() )
    {
        printf("DNI client application : First connect failed. Unable to continue\n");
	error  = 1;
    }

    return (error);
}


/*
 * main local
 */
int clnt_main_local (void) 
{
    int error = 0;
    int j = 0;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

    /* setup data to send */
    for (j=0; j<DATA_LEN; j++)
    {
        out_data[j] = j & 0xff;
    }

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

    return (error);
}


/*
 * timeout handler
 */
int clnt_timeout_handler (void) 
{
  int error = 0;

  //  CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

  //  CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

  return (error);
}



/*
 * notification processing
 */
int clnt_notification (uint32_t fd, void* context, uint32_t event_flags)
{
    int error = 0;
    int len;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (fd = %d, context = %p, event_flags = %x)\n",
		      __FUNCTION__, fd, context, event_flags);

    switch (event_flags) 
    {
        case CVM_SO_RX_CLOSE:
	     /* server is also closing the connection; ignore the notification */
	     break;

        case CVM_SO_RX_RST:
        case CVM_SO_TX_RST:
        case CVM_SO_CONN_ERROR:
     
            cvm_so_close (fd);

	    if (event_flags & CVM_SO_CONN_ERROR)
	    {
	        printf("DNI client application : Unable to establish connection [error=0x%X]; moving to the next one\n", errno);
		printf("i=%d\n", loop_count);
	    }

            loop_count++;
	    CVMX_SYNCWS;


            if (loop_count >= MAX_LOOP_COUNT)
	    {
                printf("DNI clientapplication test ended after %d iterations\n", loop_count);
	    }
	    else
	    {
                /* initiate another connect */
                if (clnt_do_single_connect() )
                {
		    printf("DNI client application : New connect failed. Unable to continue; itteration count is %d\n", loop_count);
	            error = 1;
                }
	    }
            break;

        case CVM_SO_CONN_ESTABLISHED:

            len = cvm_so_send(fd, (void*)out_data, DATA_LEN, 0);
            if (len == -1)
            {
	        printf("DNI client application : send failed [fd = %lld, iteration = %d, error = 0x%X]\n", CAST64(fd), loop_count, errno);
   	        cvm_so_close(fd);
		error = 1;
		break;
            }

	    if (len != DATA_LEN)
	    {
	        printf("DNI client application : send failed [fd = %lld, iteration = %d, error = 0x%X]\n", CAST64(fd), loop_count, errno);
   	        cvm_so_close(fd);
		error = 1;
		break;
	    }
	    break;


        case CVM_SO_RETX_FAILED:
            break;

        case CVM_SO_CAN_SEND:
            break;

        case CVM_SO_CAN_READ:

            len = cvm_so_recv(fd, (void*)in_data, DATA_LEN+64, 0);
            if (len == -1)
            {
  	        printf("DNI client application : recv failed [fd  = %lld, iteration = %d, error = 0x%X]\n", CAST64(fd), loop_count, errno);
   	        cvm_so_close(fd);
                error = 1;
		break;
	    }

	    if (len != DATA_LEN)
	    {
	        printf("DNI client application : recv length mismatch [fd  = %lld, iteration = %d, len = %d]\n", CAST64(fd), loop_count, len);
   	        cvm_so_close(fd);
		error = 1;
		break;
	    }

	    if (memcmp( (void*)out_data, (void*)in_data, DATA_LEN) )
	    {
	        printf("DNI client application : send and recv data mismatch [fd  = %lld, iteration = %d]\n", CAST64(fd), loop_count);
   	        cvm_so_close(fd);
                error = 1;
		break;
	    }


	    /* close the connection */
            cvm_so_close(fd);

            loop_count++;
	    CVMX_SYNCWS;

	    if (!error)
	    {
	        if (loop_count >= MAX_LOOP_COUNT)
	        {
                    printf("DNI client application test ended after %d iterations\n", loop_count);
	        }
                else
		{
                    if (clnt_do_single_connect() )
                    {
                        printf("DNI client application : New connect failed. Unable to continue\n");
	                error = 1;
                    }
		}
	    }
	    break;


        case CVM_SO_CAN_ACCEPT:
            break;

    } /* break */

    return (error);
}


/*
 * global exit
 */
int clnt_exit_global (void)
{
    int error = 0;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

    return (error);
}


/*
 * local exit
 */
int clnt_exit_local (void) 
{
    int error = 0;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

    return (error);
}


/*
 * do a single connect
 */
int clnt_do_single_connect(void)
{
#ifdef INET6
    int fd;
    int error = 0;
    struct cvm_ip6_sockaddr_in6 laddr;
    struct cvm_ip6_sockaddr_in6 faddr;
    struct cvm_ip6_in6_addr faddr6;

    faddr6.cvm_ip6_s6_addr32 [0] = 0x22334455;
    faddr6.cvm_ip6_s6_addr32 [1] = 0x667788aa;
    faddr6.cvm_ip6_s6_addr32 [2] = 0x12345678;
    faddr6.cvm_ip6_s6_addr32 [3] = 0xabcdef34;

    fd = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
    if (fd < 0)
    {
        printf("DNI client application : unable to create socket [iteration = %d, error = 0x%X]\n", loop_count, errno);
        return (1);
    }

    error = cvm_so_activate_notification (fd, NULL);
    if (error) 
    {
        printf("DNI client application : unable to activate notification [fd = %d, iteration = %d]\n", fd, loop_count);
        cvm_so_close (fd);
        return (1);
    }

    /* connect to remote address */
    faddr.sin6_family = CVM_SO_AF_INET6;
    CVM_TCP_MEMCPY (faddr.sin6_addr, faddr6, sizeof (struct cvm_ip6_in6_addr));
    faddr.sin6_port = cvm_common_htons(REMOTE_PORT);
    faddr.sin6_len = sizeof(faddr);

    error = cvm_so_connect (fd, (struct cvm_so_sockaddr*) &faddr,
        sizeof(struct cvm_ip6_sockaddr_in6));
    if (error < 0)
    {
        if (errno != CVM_COMMON_EINPROGRESS)
	{
            printf("DNI client application : connect request failed [fd = 0x%d, iteration = %d, error = 0x%X]\n", fd, loop_count, errno);
            cvm_so_close(fd);
            return (1);
	}
    }

    return (0);
#else
    int fd;
    int error = 0;
    struct cvm_ip_sockaddr_in laddr;
    struct cvm_ip_sockaddr_in faddr;



    fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
    if (fd < 0)
    {
        printf("DNI client application : unable to create socket [iteration = %d, error = 0x%X]\n", loop_count, errno);
        return (1);
    }

    error = cvm_so_activate_notification (fd, NULL);
    if (error) 
    {
        printf("DNI client application : unable to activate notification [fd = %d, iteration = %d]\n", fd, loop_count);
        cvm_so_close (fd);
        return (1);
    }

    /* setup the bind info */
    laddr.sin_family = CVM_SO_AF_INET;
    laddr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
    laddr.sin_port = cvm_common_htons(current_rport);
    laddr.sin_len = sizeof(laddr);

    error = cvm_so_bind(fd, (struct cvm_so_sockaddr*)&laddr, sizeof(struct cvm_so_sockaddr));
    if (error)
    {
        printf("DNI client application : unable to bind new socket [fd = %d, iteration = %d, error = 0x%X]\n", fd, loop_count, errno);
	cvm_so_close(fd);
        return (1);
    }

    current_rport++;
    CVMX_SYNCWS;

    /* connect to remote address */
    faddr.sin_family = CVM_SO_AF_INET;
    faddr.sin_addr.s_addr = (uint32_t)REMOTE_IP_ADDR;
    faddr.sin_port = cvm_common_htons(REMOTE_PORT);
    faddr.sin_len = sizeof(faddr);

    error = cvm_so_connect(fd, (struct cvm_so_sockaddr*)&faddr, sizeof(struct cvm_so_sockaddr));
    if (error < 0)
    {
        if (errno != CVM_COMMON_EINPROGRESS)
	{
            printf("DNI client application : connect request failed [fd = 0x%d, iteration = %d, error = 0x%X]\n", fd, loop_count, errno);
            cvm_so_close(fd);
            return (1);
	}
    }

    return (0);
#endif
}

#endif /* #if defined (DNI_APP_CLIENT) */

#endif
