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

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#endif
#include "socket.h"
#include "socketvar.h"

#include "cvm-tcp-var.h"

#include "cvm-socket.h"

#include "inic.h"


#define DATA_LEN 512  /* 512 bytes of data */

/*
 * Client application sample code
 */
#ifdef INET6
int client_application()
{
    int i=0, j=0;
    int error = 0;
    int loop_count = 1000;
    int fd;

    struct cvm_so_sockaddr_storage ss;
    struct cvm_ip6_sockaddr_in6 laddr6;
    struct cvm_ip6_sockaddr_in6 *faddr6 = (struct cvm_ip6_sockaddr_in6 *)&ss;

    int local_port_number = 1600;
    struct cvm_ip6_in6_addr foreign_address6; 
    uint16_t foreign_port_number = cvm_common_htons(80);

    char out_data[DATA_LEN];
    char in_data[DATA_LEN+512];
    int send_len = 0, recv_len = 0;

    printf("Starting client_application test for %d iterations\n", loop_count);

    foreign_address6.cvm_ip6_s6_addr32 [0] = 0x22334455; 
    foreign_address6.cvm_ip6_s6_addr32 [1] = 0x667788aa; 
    foreign_address6.cvm_ip6_s6_addr32 [2] = 0x12345678; 
    foreign_address6.cvm_ip6_s6_addr32 [3] = 0xabcdef34; 

    printf ("%s connecting to %s\n", __FUNCTION__, cvm_ip6_ip6_sprintf (&foreign_address6));

    /* setup data to send */
    for (j=0; j<DATA_LEN; j++)
    {
        out_data[j] = j & 0xff;
    }

    for (i=0; i<loop_count; i++)
    {
        fd = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
        if (fd < 0)
        {
            printf("client_application : unable to create socket [iteration = %d, error = 0x%X]\n", i, errno);
            break;
        }

    /* setup the bind info */
    memset (&laddr6, '\0', sizeof (laddr6));

    /* setup the bind info */
    laddr6.sin6_family = CVM_SO_AF_INET6;
    laddr6.sin6_addr = cvm_ip6_in6addr_any;
    laddr6.sin6_port = cvm_common_htons (local_port_number+i);
    laddr6.sin6_len = sizeof (laddr6);

        error = cvm_so_bind(fd, (struct cvm_so_sockaddr*)&laddr6, sizeof(struct cvm_so_sockaddr));
        if (error)
        {
            printf("client_application : unable to bind new listening socket [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	/* connect to remote address */
        faddr6->sin6_family = CVM_SO_AF_INET;
        CVM_TCP_MEMCPY (faddr6->sin6_addr, foreign_address6, sizeof (struct cvm_ip6_in6_addr));
        faddr6->sin6_port = foreign_port_number;
        faddr6->sin6_len = sizeof (struct cvm_ip6_sockaddr_in6);

        //error = cvm_so_connect(fd, (struct cvm_so_sockaddr*)faddr6, sizeof(struct cvm_so_sockaddr_storage));
        error = cvm_so_connect(fd, (struct cvm_so_sockaddr*)faddr6, sizeof(struct cvm_ip6_sockaddr_in6));
        if (error)
        {
            printf("client_application : connect failed [fd = 0x%d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	/* send data in blocking mode */
        send_len = cvm_so_send(fd, (void*)out_data, DATA_LEN, 0);
        if (send_len == -1)
        {
            printf("client_application : send failed [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno); 
   	    cvm_so_close(fd);
            break;
        }

	/* receive data in blocking mode */
        //recv_len = cvm_so_recv(fd, (void*)in_data, DATA_LEN+512, 0);
        recv_len = cvm_so_recv(fd, (void*)in_data, DATA_LEN, 0);
        if (recv_len == -1)
        {
            printf("client_application : recv failed [fd  = %d, iteration = %d, error = 0x%X]\n", fd, i, errno);
   	    cvm_so_close(fd);
            break;
	}

	if (send_len != recv_len)
	{
	    printf("client_application : send and recv lengths mismatch [fd  = %d, iteration = %d, send_len = %d, recv_len = %d]\n", fd, i, send_len, recv_len);
   	    cvm_so_close(fd);
            break;
	}

	if (memcmp( (void*)out_data, (void*)in_data, send_len) )
	{
	    printf("client_application : send and recv data mismatch [fd  = %d, iteration = %d]\n", fd, i);
   	    cvm_so_close(fd);
            break;
	}

	/* close the connection */
        cvm_so_close(fd);
    }

    printf("client_application test ended after %d iterations\n", i);

    /* we are done - go in a while loop for now */
    while(1);

    return (0);
}
#else
int client_application()
{
    int i=0, j=0;
    int error = 0;
    int loop_count = 1000;
    int fd;
    struct cvm_ip_sockaddr_in laddr;
    struct cvm_ip_sockaddr_in faddr;

    int local_port_number = 1600;
    int foreign_address = 0xC0A83096;  /* 192.168.48.150 */
    uint16_t foreign_port_number = cvm_common_htons(1500);

    char out_data[DATA_LEN];
    char in_data[DATA_LEN+512];
    int send_len = 0, recv_len = 0;

    printf("Starting client_application test for %d iterations\n", loop_count);

    /* setup data to send */
    for (j=0; j<DATA_LEN; j++)
    {
        out_data[j] = j & 0xff;
    }

    for (i=0; i<loop_count; i++)
    {
        fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
        if (fd < 0)
        {
            printf("client_application : unable to create socket [iteration = %d, error = 0x%X]\n", i, errno);
            break;
        }

        /* setup the bind info */
        laddr.sin_family = CVM_SO_AF_INET;
        laddr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
        laddr.sin_port = cvm_common_htons(local_port_number+i);
        laddr.sin_len = sizeof(laddr);	

        error = cvm_so_bind(fd, (struct cvm_so_sockaddr*)&laddr, sizeof(struct cvm_so_sockaddr));
        if (error)
        {
            printf("client_application : unable to bind new listening socket [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	/* connect to remote address */
        faddr.sin_family = CVM_SO_AF_INET;
        faddr.sin_addr.s_addr = (uint32_t)foreign_address;
        faddr.sin_port = foreign_port_number;
        faddr.sin_len = sizeof(faddr);

        error = cvm_so_connect(fd, (struct cvm_so_sockaddr*)&faddr, sizeof(struct cvm_so_sockaddr));
        if (error)
        {
            printf("client_application : connect failed [fd = 0x%d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	/* send data in blocking mode */
        send_len = cvm_so_send(fd, (void*)out_data, DATA_LEN, 0);
        if (send_len == -1)
        {
            printf("client_application : send failed [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno); 
   	    cvm_so_close(fd);
            break;
        }

	/* receive data in blocking mode */
        recv_len = cvm_so_recv(fd, (void*)in_data, DATA_LEN+512, 0);
        if (recv_len == -1)
        {
            printf("client_application : recv failed [fd  = %d, iteration = %d, error = 0x%X]\n", fd, i, errno);
   	    cvm_so_close(fd);
            break;
	}

	if (send_len != recv_len)
	{
	    printf("client_application : send and recv lengths mismatch [fd  = %d, iteration = %d, send_len = %d, recv_len = %d]\n", fd, i, send_len, recv_len);
   	    cvm_so_close(fd);
            break;
	}

	if (memcmp( (void*)out_data, (void*)in_data, send_len) )
	{
	    printf("client_application : send and recv data mismatch [fd  = %d, iteration = %d]\n", fd, i);
   	    cvm_so_close(fd);
            break;
	}

	/* close the connection */
        cvm_so_close(fd);
    }

    printf("client_application test ended after %d iterations\n", i);

    /* we are done - go in a while loop for now */
    while(1);

    return (0);
}
#endif

#ifdef APP_OCTEON_2_OCTEON
/* Loop:
	Opens a TCP session with server
        After connection is established, sends one packet to the server
        Receives data from the server in a tight-loop
	Breaks out of the loop when server is done with its data
   Goes back to loop for next session
*/
int client_application_rcv_only_zc ()
{
    int i=0, j=0;
    int loop_count = 1;
    int fd;
    struct cvm_ip_sockaddr_in laddr;
    struct cvm_ip_sockaddr_in faddr;
    int               error = -1;
    int               len = 0;
    struct cvm_so_iovec  *vector=NULL;

    int local_port_number = 1600;
    int foreign_address = 0xC0A83001;  /* 192.168.48.1 */
    uint16_t foreign_port_number = cvm_common_htons(80);

    char out_data[DATA_LEN];
    char in_data[DATA_LEN+512];

    int send_len = 0, recv_len = 0;

    printf("Starting client_application test for %d iterations\n", loop_count);

    /* setup data to send */
    for (j=0; j<DATA_LEN; j++)
    {
        out_data[j] = j & 0xff;
    }

    for (i=0; i<loop_count; i++)
    {
        fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
        if (fd < 0)
        {
            printf("client_application : unable to create socket [iteration = %d, error = 0x%X]\n", i, errno);
            break;
        }

        /* setup the bind info */
        laddr.sin_family = CVM_SO_AF_INET;
        laddr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
        laddr.sin_port = cvm_common_htons(local_port_number+i);
        laddr.sin_len = sizeof(laddr);	

        error = cvm_so_bind(fd, (struct cvm_so_sockaddr*)&laddr, sizeof(struct cvm_so_sockaddr));
        if (error)
        {
            printf("client_application : unable to bind new listening socket [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	/* connect to remote address */
        faddr.sin_family = CVM_SO_AF_INET;
        faddr.sin_addr.s_addr = (uint32_t)foreign_address;
        faddr.sin_port = foreign_port_number;
        faddr.sin_len = sizeof(faddr);

        error = cvm_so_connect(fd, (struct cvm_so_sockaddr*)&faddr, sizeof(struct cvm_so_sockaddr));
        if (error)
        {
            printf("client_application : connect failed [fd = 0x%d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	printf ("Sending %d bytes\n", DATA_LEN);
	/* send data in blocking mode */
        send_len = cvm_so_send(fd, (void*)out_data, DATA_LEN, 0);
        if (send_len == -1)
        {
            printf("client_application : send failed [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno); 
   	    cvm_so_close(fd);
            break;
        }

        while (1)
        {
            vector = NULL;

            /* Zero-copy read */
            len = cvm_so_read_zc (fd, &vector);

	    printf ("read %d bytes\n", len);
    
            if (len == 0)
            {
                CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : recv on fd %d failed due to peer initiated close (error = 0x%X)\n", fd, errno);
	        if (errno == CVM_COMMON_EAGAIN)
	        {
	            return 0;
	        }
	        else
	        {
                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : recv on fd %d failed due to peer initiated close (error = 0x%X)\n", fd, errno);
   	            cvm_so_close(fd);
                    return (error);
	        }
            }

            if (len == -1)
            {
                CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : error doing recv on fd %d (error = 0x%X)\n", fd, errno);
                /* do this only for non-blocking sockets */
	        if (errno == CVM_COMMON_EAGAIN)
	        {
                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "deal_with_data_zc : nothing to recv on fd %d (error = 0x%X)\n", fd, errno);
	            return 0;
	        }
	        else
	        {
                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : error doing recv on fd %d (error = 0x%X)\n", fd, errno);
   	            cvm_so_close(fd);
                    return (error);
	        }
            }

            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "++ %d iovecs of data received (fd = %d) ++\n", 
                     vector->iovec_count, fd);
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

            /* free the iovec */
            cvm_so_free_zc_iovec (vector);

	    printf ("RX %d bytes\n", len);
     }

	if (send_len != recv_len)
	{
	    printf("client_application : send and recv lengths mismatch [fd  = %d, iteration = %d, send_len = %d, recv_len = %d]\n", fd, i, send_len, recv_len);
   	    cvm_so_close(fd);
            break;
	}

	if (memcmp( (void*)out_data, (void*)in_data, send_len) )
	{
	    printf("client_application : send and recv data mismatch [fd  = %d, iteration = %d]\n", fd, i);
   	    cvm_so_close(fd);
            break;
	}

	/* close the connection */
        cvm_so_close(fd);
    }

    printf("client_application test ended after %d iterations\n", i);

    /* we are done - go in a while loop for now */
    while(1);

    return (0);
}


extern CVMX_SHARED char    *g_send_data; 
extern CVMX_SHARED char    *g_recv_data; 
extern CVMX_SHARED uint32_t g_send_data_size; 
CVMX_SHARED uint32_t        g_recv_data_size=0; 

/* Loop:
	Opens a TCP session with server
        After connection is established, sends one packet to the server
        Receives data from the server in a tight-loop
	Breaks out of the loop when server is done with its data
	Compares the data received from server against predefined pattern to ensure data integrity
   Goes back to loop for next session
*/
int client_application_rcv_only_zc_verify ()
{
    int               i=0, j=0;
    int               loop_count = 100000;
    int               fd;
    int               error = -1;
    int               len = 0;
    int               local_port_number = 1600;
    int               foreign_address = 0xC0A83001;  /* 192.168.48.1 */
    uint16_t          foreign_port_number = cvm_common_htons(80);
    char              out_data[DATA_LEN];
    int               _iter=0;
    int               _i=0;
    cvmx_buf_ptr_t    ptr;
    int               send_len = 0;
    struct cvm_so_iovec       *vector=NULL;
    struct cvm_ip_sockaddr_in laddr;
    struct cvm_ip_sockaddr_in faddr;

    printf("Starting client_application test for %d iterations\n", loop_count);

    /* setup data to send */
    for (j=0; j<DATA_LEN; j++)
    {
        out_data[j] = j & 0xff;
    }

    for (_i=0; _i<loop_count; _i++)
    {
	printf ("count:%d starting...\n", _iter);
        fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
        if (fd < 0)
        {
            printf("client_application : unable to create socket [iteration = %d, error = 0x%X]\n", i, errno);
            break;
        }

        /* setup the bind info */
        laddr.sin_family = CVM_SO_AF_INET;
        laddr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
        laddr.sin_port = cvm_common_htons(local_port_number+_i);
        laddr.sin_len = sizeof(laddr);	

        error = cvm_so_bind(fd, (struct cvm_so_sockaddr*)&laddr, sizeof(struct cvm_so_sockaddr));
        if (error)
        {
            printf("client_application : unable to bind new listening socket [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	/* connect to remote address */
        faddr.sin_family = CVM_SO_AF_INET;
        faddr.sin_addr.s_addr = (uint32_t)foreign_address;
        faddr.sin_port = foreign_port_number;
        faddr.sin_len = sizeof(faddr);

        error = cvm_so_connect(fd, (struct cvm_so_sockaddr*)&faddr, sizeof(struct cvm_so_sockaddr));
        if (error)
        {
            printf("client_application : connect failed [fd = 0x%d, iteration = %d, error = 0x%X]\n", fd, i, errno);
	    cvm_so_close(fd);
            break;
        }

	printf ("Sending %d bytes\n", DATA_LEN);
	/* send data in blocking mode */
        send_len = cvm_so_send(fd, (void*)out_data, DATA_LEN, 0);
        if (send_len == -1)
        {
            printf("client_application : send failed [fd = %d, iteration = %d, error = 0x%X]\n", fd, i, errno); 
   	    cvm_so_close(fd);
            break;
        }

	int offset=0;
        while (1)
        {
            vector = NULL;

	    //cvmx_wait (1000000);

            /* Zero-copy read */
            len = cvm_so_read_zc (fd, &vector);

    
	    //printf ("read_Zc: %d bytes\n", len);
            if (len == 0)
            {
                CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : recv on fd %d failed due to peer initiated close (error = 0x%X)\n", fd, errno);
                printf ("deal_with_data_zc : recv on fd %d failed due to peer initiated close (error = 0x%X)\n", fd, errno);
		goto compare;
	        if (errno == CVM_COMMON_EAGAIN)
	        {
	            return 0;
	        }
	        else
	        {
                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : recv on fd %d failed due to peer initiated close (error = 0x%X)\n", fd, errno);
   	            cvm_so_close(fd);
                    return (error);
	        }
            }

            if (len == -1)
            {
                printf ( "deal_with_data_zc : error doing recv on fd %d (error = 0x%X)\n", fd, errno);
		goto compare;
                /* do this only for non-blocking sockets */
	        if (errno == CVM_COMMON_EAGAIN)
	        {
                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "deal_with_data_zc : nothing to recv on fd %d (error = 0x%X)\n", fd, errno);
	            return 0;
	        }
	        else
	        {
                    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : error doing recv on fd %d (error = 0x%X)\n", fd, errno);
   	            cvm_so_close(fd);
                    return (error);
	        }
            }

            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "++ %d iovecs of %d bytes data received (fd = %d) ++\n", 
	                        vector->iovec_count, len, fd);
            CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

            /* this will process and free the iovec */
            for (i=0; i<vector->iovec_count; i++)
            {
                CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_8, "%s: iovec_count: %d data_size: %ld\n",
	                            __FUNCTION__, i, vector->iovec_ptr_array [i].iov_len);
                ptr = (cvmx_buf_ptr_t) vector->iovec_ptr_array[i].iov_base;
	        memcpy ((void *)g_recv_data+offset, (void *)ptr.s.addr, vector->iovec_ptr_array[i].iov_len);
		g_recv_data_size+=vector->iovec_ptr_array[i].iov_len;
		offset+=vector->iovec_ptr_array[i].iov_len;
            }

            /* free iovecs */
            cvm_so_free_zc_iovec (vector);
        }

compare:
   {
     int _ret;
     _ret = memcmp (g_recv_data, g_send_data, g_recv_data_size);
     if (_ret == 0)
     {
	printf ("count: %d Sent and recv data identical (sent: %d recv: %d)\n", _iter, g_send_data_size, g_recv_data_size);
     }
     else
     {
	printf ("count: %d Sent and recv data different (sent: %d recv: %d) _ret: %d\n", _iter, g_send_data_size, g_recv_data_size, _ret);

	break;

      }

      memset (g_recv_data, 0, g_send_data_size);
      g_recv_data_size=0;
    }

    printf("closing socket: %d\n", fd);
    cvm_so_close(fd);

    _iter++;
   }

   printf("client_application test ended after %d iterations\n", _iter);

   /* we are done - go in a while loop for now */
   while(1);

   return (0);
}
#endif
