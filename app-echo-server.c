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
#include "cvmx-coremask.h"
#include "cvmx-sysinfo.h"

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

#include "inic.h"

#if defined(CVM_UDP_ECHO_SERVER)
int udp_echo_server_application(void);
#endif


/*
 * sample non-blocking echo server application
 */

cvm_so_status sock_status[MAX_POLL_SOCKETS];


#define DATA_BUFFER_SIZE (2*1024)

#if defined(CVM_COMBINED_APP_STACK)
#define MAX_SOCKETS       65533 /* 1 listening socket, 65532 data sockets */
#else
#define MAX_SOCKETS       63   /* 1 listening socket, 62 data sockets */
#endif
#define HEADSOCK_BACKLOG  35
#define MAX_ACCEPT_MULTI  15


int max_accept_multi = 0;
int free_count = MAX_SOCKETS;

struct _socket_info
{
   int                       fd;

#ifdef INET6

#ifdef APP_ECHO_SERVER_TCP_v4_v6
   union 
   {
       struct cvm_so_sockaddr_storage addr6_ss;
       struct cvm_ip6_sockaddr_in6    addr6_in6;
   } addr6;

   struct cvm_ip_sockaddr_in addr;

#else /* APP_ECHO_SERVER_TCP_v4_v6 */

   union 
   {
       struct cvm_so_sockaddr_storage addr6_ss;
       struct cvm_ip6_sockaddr_in6    addr6_in6;
   } addr6;

#endif /* APP_ECHO_SERVER_TCP_v4_v6 */

#else /* INET6 */

   struct cvm_ip_sockaddr_in addr;

#endif /* INET6 */

   int                       addrlen;
   int                       mode;
#ifdef IPERF_SERVER
   uint64_t                  bytes;
   uint64_t                  start_cycles;
   uint64_t                  end_cycles;
   uint8_t                   use_for_iperf;
#endif
};


typedef struct _socket_info socket_info_t;


struct _sockets
{
    int free_count;
    socket_info_t sock[MAX_SOCKETS];
};

typedef struct _sockets sockets_t;


#ifdef IPERF_SERVER
char* get_ip_addr_string(uint32_t ipaddr)
{
    static char ipaddr_str[32];

    sprintf(ipaddr_str, "%d.%d.%d.%d",
            (ipaddr >> 24) & 0xff,
	    (ipaddr >> 16) & 0xff, 
	    (ipaddr >> 8) & 0xff,
	    (ipaddr) & 0xff);

    return (ipaddr_str);
}

void display_iperf_results(sockets_t* sockets)
{
    int i = 0;
    float start_in_secs = 0.0;
    float end_in_secs = 0.0;
    float total_bytes_in_gig = 0;
    float rate_in_mbps = 0;
    cvmx_sysinfo_t *appinfo = cvmx_sysinfo_get();

    printf("\n");

    for (i=0; i<MAX_SOCKETS; i++)
    {
        if (sockets->sock[i].use_for_iperf)
	{
	    end_in_secs = ( (float)(sockets->sock[i].end_cycles-sockets->sock[i].start_cycles)/(float)appinfo->cpu_clock_hz );
            total_bytes_in_gig = (float)(sockets->sock[i].bytes/(float)(1024.0*1024.0*1024.0) );
            rate_in_mbps = (float)(((float)(sockets->sock[i].bytes*8)/(end_in_secs)))/(float)(1000.0*1000.0);

	    printf("iperf: [%d]  %3.1f-%3.1f sec    %4.2f GBytes    %3.0f Mbits/sec\n", i, start_in_secs, end_in_secs, total_bytes_in_gig, rate_in_mbps);

	    sockets->sock[i].bytes = 0;
	    sockets->sock[i].start_cycles = 0;
	    sockets->sock[i].end_cycles = 0;
	    sockets->sock[i].use_for_iperf = 0;
	}
    }

    printf("\n");
}

#endif

int get_next_socket_slot(sockets_t* sockets)
{
    int i=0;
    int slot = -1;

    for (i=0; i<MAX_SOCKETS; i++)
    {
        if (sockets->sock[i].fd == 0)
        {
            slot = i;
	    sockets->free_count--;
            break;
        }
    }

    return (slot);
}


int build_poll_list(cvm_so_status* list, sockets_t* sockets, int max)
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

struct cvm_so_accepted_sock_info single_accept[MAX_ACCEPT_MULTI];

int deal_with_new_connection(sockets_t* sockets, int rd_ready_idx)
{
    int ret = -1;
    int slot_id = 0;
    int error = 0;
    int i = 0;
    struct cvm_so_sockaddr_multi addr_multi;

    /* addr multi nitializations */
    addr_multi.sock_info = single_accept;
    addr_multi.sock_entry_count = MAX_ACCEPT_MULTI;

    if (sockets->free_count < MAX_ACCEPT_MULTI)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "deal_with_new_connection : no space to hold new connections (free count = %d)\n", sockets->free_count);
        return (ret);
    }

    error = cvm_so_accept_multi(sockets->sock[rd_ready_idx].fd, &addr_multi, 0);
    if (error)
    {
        if (addr_multi.sock_entry_count == 0)
	{
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "deal_with_new_connection : accept_multi failed (error = 0x%X)\n", errno);
	    return (ret);
	}
    }

    if (max_accept_multi < addr_multi.sock_entry_count) max_accept_multi = addr_multi.sock_entry_count;

    for (i=0; i<addr_multi.sock_entry_count; i++)
    {
        slot_id = get_next_socket_slot(sockets);
        if (slot_id == -1)
	{
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "deal_with_new_connection : no space in fd array\n");
            return (ret);
	}


        sockets->sock[slot_id].fd = addr_multi.sock_info[i].sockfd;
        sockets->sock[slot_id].addrlen = addr_multi.sock_info[i].addrlen;
#ifdef INET6
	memcpy(&sockets->sock[slot_id].addr6, &addr_multi.sock_info[i].addr,  addr_multi.sock_info[i].addrlen);
#else
	memcpy(&sockets->sock[slot_id].addr, &addr_multi.sock_info[i].addr,  addr_multi.sock_info[i].addrlen);
#endif

#ifdef IPERF_SERVER
	sockets->sock[slot_id].bytes = 0;
	sockets->sock[slot_id].start_cycles = 0;
        sockets->sock[slot_id].use_for_iperf = 1;
	printf("iperf: connected to %s port %d\n",  get_ip_addr_string(sockets->sock[slot_id].addr.sin_addr.s_addr), sockets->sock[slot_id].addr.sin_port);
#endif

	if (free_count > sockets->free_count) free_count = sockets->free_count;

        /* set the newly created socket as non-blocking */
	sockets->sock[slot_id].mode = FNONBIO;
        cvm_so_fcntl(sockets->sock[slot_id].fd, sockets->sock[slot_id].mode, 1);

#ifdef INET6
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "++ A new connection has been accepted (fd = %d, fport = %x) ++\n", 
                sockets->sock[slot_id].fd, sockets->sock[slot_id].addr6.addr6_in6.sin6_port);
#else
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "++ A new connection has been accepted (fd = %d, fport = %x) ++\n", 
                sockets->sock[slot_id].fd, sockets->sock[slot_id].addr.sin_port);
#endif
    }

    ret = 0;
    return (ret);
}

int deal_with_data(sockets_t* sockets, int index)
{
    char buffer[DATA_BUFFER_SIZE];
    int error = -1;
    int len = 0;
    int fd = sockets->sock[index].fd;

    len = cvm_so_recv(fd, (void*)buffer, DATA_BUFFER_SIZE, 0);
    if (len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data : recv on fd %d failed (error = 0x%X)\n", fd, errno);
	sockets->sock[index].fd = 0;
	sockets->free_count++;
   	cvm_so_close(fd);

#ifdef IPERF_SERVER
	sockets->sock[index].end_cycles = cvmx_get_cycle();

	/* check if all the iperf connections have been terminated */    
	if (sockets->free_count >= (MAX_SOCKETS-1) )
	{
            display_iperf_results(sockets);
	}
#endif

        return (error);
    }

    if (len == 0)
    {
#ifdef INET6
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "deal_with_data : connection on socket fd %d has been terminated [sport = %x] \n", 
                 sockets->sock[index].fd, sockets->sock[index].addr6.addr6_in6.sin6_port);
#else
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "deal_with_data : connection on socket fd %d has been terminated [sport = %x] \n", 
                 sockets->sock[index].fd, sockets->sock[index].addr.sin_port);
#endif
	sockets->sock[index].fd = 0;
	sockets->free_count++;
	cvm_so_close(fd);
        return (error);
    }

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_7, "++ %d bytes of data received (fd = %d) ++\n", len, fd);

#ifdef IPERF_SERVER
    sockets->sock[index].bytes += len;
    if (sockets->sock[index].start_cycles == 0x0) sockets->sock[index].start_cycles = cvmx_get_cycle();
#else

do_send_again:
    error = cvm_so_send(fd, (void*)buffer, len, 0);
    if (error == -1)
    {
        //CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data : send failed (error = 0x%X)\n", errno); 
	if (errno == CVM_COMMON_EAGAIN)
	{
	    goto do_send_again;
	}

	sockets->sock[index].fd = 0;
	sockets->free_count++;
   	cvm_so_close(fd);
        return (error);
    } 

#endif /* IPERF_SERVER */

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "++ %d bytes of data sent (fd = %d) ++\n", len, fd);

    return (0);
}


#ifdef USE_ZERO_COPY 
int process_read_iovec (struct cvm_so_iovec *vector)
{
    int retval=-1, i;

    for (i=0; i<vector->iovec_count; i++)
    {
        CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_8, "%s: iovec_count: %d data_size: %ld\n",
	         __FUNCTION__, i, vector->iovec_ptr_array [i].iov_len);
    }

    /* free iovecs */
    retval = cvm_so_free_zc_iovec (vector);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_8, "%s: free iovec returned: 0x%x\n", __FUNCTION__, retval);

    return (retval);
}
 
/* Zero-copy echo: read and write with same buffer */
/* This function:
   - does zero-copy read
   - reuses the same iovec to write back 
   - does zero-copy write
 */
int deal_with_data_zc_reuse_iovec (sockets_t* sockets, int index)
{
    int error = -1;
    int len = 0;
    int fd = sockets->sock[index].fd;
    struct cvm_so_iovec *vector=NULL;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "%s: begins for socket: %d\n", __FUNCTION__, fd);
    len = cvm_so_read_zc (fd, &vector);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "%s: back from cvm_so_read_zc \n", __FUNCTION__);

    if (len == 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : recv on fd %d failed due to peer initiated close (error = 0x%X)\n", fd, errno);
	if (errno == CVM_COMMON_EAGAIN)
	{
	    //goto do_send_again;
	    return 0;
	}
	else
	{
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : recv on fd %d failed due to peer initiated close (error = 0x%X)\n", fd, errno);
	sockets->sock[index].fd = 0;
	sockets->free_count++;
   	cvm_so_close(fd);
        return (error);
	}
    }

    if (len == -1)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : error doing recv on fd %d (error = 0x%X)\n", fd, errno);
        /* do this only for non-blocking sockets */
        if (CVM_COMMON_EAGAIN == error) 
        {
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "deal_with_data_zc : nothing to recv on fd %d (error = 0x%X)\n", fd, errno);
	    return 0;
        }
	if (errno == CVM_COMMON_EAGAIN)
	{
	    //printf ("trying send again\n");
	    //goto do_send_again;
	    return 0;
	}
	else
	{
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : error doing recv on fd %d (error = 0x%X)\n", fd, errno);
	sockets->sock[index].fd = 0;
	sockets->free_count++;
   	cvm_so_close(fd);
        return (error);
	}
    }

#if 0
    if (len == -1)
    {
        /* do this only for non-blocking sockets */
        if (CVM_COMMON_EAGAIN == error)
        {
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "deal_with_data_zc : nothing to recv on fd %d (error = 0x%X)\n", fd, errno);
	    return 0;
        }
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "deal_with_data_zc : recv on fd %d failed (error = 0x%X)\n", fd, errno);
	sockets->sock[index].fd = 0;
	sockets->free_count++;
   	cvm_so_close(fd);
        return (error);
    }

    if (len == 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "deal_with_data_zc : connection on socket fd %d has been terminated [sport = %x] \n", 
                 sockets->sock[index].fd, sockets->sock[index].addr.sin_port);

	sockets->sock[index].fd = 0;
	sockets->free_count++;
	cvm_so_close(fd);
        return (error);
    }
#endif

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "%s: cvm_so_read_zc done...calling cvm_so_write_zc\n", __FUNCTION__);

do_writezc_again:
    error = cvm_so_write_zc (fd, vector, 1);
    if (error<0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "%s: cvm_so_write_zc failed (error = 0x%X)\n", __FUNCTION__, errno); 
        CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "===============================================\n");
	if (errno == CVM_COMMON_EAGAIN)
	{
	    goto do_writezc_again;
	}
	else
	{
	    cvm_so_free_zc_iovec (vector);
	    sockets->sock[index].fd = 0;
	    sockets->free_count++;
   	    cvm_so_close(fd);
            return (error);
	}
    } 

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_7, "++ %d iovecs of data sent (fd = %d) ++\n", 
             vector->iovec_count, fd);

    return 0;
}

#ifdef APP_OCTEON_2_OCTEON

extern CVMX_SHARED char     *g_send_data; 
extern CVMX_SHARED uint32_t g_send_data_size; 
CVMX_SHARED int g_sent_all=0;
int  _iter=0;

/* 
  The following function:
    receives a packet from the client
    goes in a tight loop trying to send data to the client
    breaks out of the function when all of the data has been sent to client
 */
int deal_with_data_zc_verify (sockets_t* sockets, int index)
{
    int                   error = -1;
    int                   len = 0;
    int                   fd = sockets->sock[index].fd;
    struct cvm_so_iovec  *vector=NULL;
    struct cvm_so_iovec  *wr_vector=NULL;
    cvmx_buf_ptr_t        ptr; 
    int                   wr_iovec_count = 0;
    int                   size = 1;
    int                   i;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "%s: begins for socket: %d\n", __FUNCTION__, fd);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    wr_vector = vector = NULL;

    /* Zero-copy read */
    len = cvm_so_read_zc (fd, &vector);
    
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
	    sockets->sock[index].fd = 0;
	    sockets->free_count++;
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
	    sockets->sock[index].fd = 0;
	    sockets->free_count++;
   	    cvm_so_close(fd);
            return (error);
	}
    }

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "++ %d iovecs of data received (fd = %d) ++\n", 
                        vector->iovec_count, fd);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

    /* this will process and free the iovec */
    process_read_iovec (vector);

   {
       size=100*1024;
       int offset=0;
       uint32_t _count=0;

       printf ("Begin of data verification iteration: %d\n", _iter);
       _iter++;
       while (_count<g_send_data_size)
       {
          /* Allocate a new zero-copy iovec to echo back the received data */
          error = cvm_so_alloc_zc_iovec (&wr_vector, size);

          if (error < 0)
          {
	      CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "%s: Failed to allocate iovec\n", __FUNCTION__);
	      return 0;
          }

          /* populate data */
          for (i=0; i<wr_vector->iovec_count; i++)
          {
              ptr = (cvmx_buf_ptr_t) wr_vector->iovec_ptr_array[i].iov_base;
              memcpy ((char *)ptr.s.addr, (char *) g_send_data+offset, wr_vector->iovec_ptr_array[i].iov_len);
	      offset+=wr_vector->iovec_ptr_array[i].iov_len;
          }

          CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
          CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "%s: zero-copy send of %d bytes (%d iovecs)\n", 
                               __FUNCTION__, size, wr_vector->iovec_count);
          CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

          wr_iovec_count = wr_vector->iovec_count;

do_send_again:
          /* Zero-copy write */
          error = cvm_so_write_zc (fd, wr_vector, 1);
    
          //if (offset%32768==0) cvmx_wait (1000000);

          if (0>error)
          {
	      if (errno == CVM_COMMON_EAGAIN)
	      {
	          //printf ("trying send again\n");
	          //cvmx_wait (100000);
	          goto do_send_again;
	      }
	      else
	      {
	          cvm_so_free_zc_iovec (wr_vector);
	          sockets->sock[index].fd = 0;
	          sockets->free_count++;
	          printf ("errno:%d closing socket\n", errno);
   	          cvm_so_close(fd);
                  return (error);
	      }
          } 

          CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
          CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "++ %d iovecs of data %d bytes sent (fd = %d) ++\n", 
                              wr_iovec_count, size, fd);
          CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

          if (error != size)
              printf ("Req send %d != actual send %d\n", error, size);

          _count+=error;

       }//while

       printf ("Sent all of %d bytes from send_file fd: %d\n", offset, fd);
       sockets->sock[index].fd = 0;
       sockets->free_count++;
       printf ("closing socket %d\n", fd);
       cvm_so_close(fd);
       g_sent_all=1;
    }
    return 0;
}
#endif //APP_OCTEON_2_OCTEON


/* Zero-copy echo: read and write with different buffers */
/* This function 
   - does zero-copy read
   - frees the read iovecv 
   - allocates a new iovec for sending data
   - performs zero-copy write 
 */

int deal_with_data_zcopy (sockets_t* sockets, int index)
{
    int               error = -1;
    int               len = 0;
    int               fd = sockets->sock[index].fd;
    struct cvm_so_iovec  *vector=NULL;
    struct cvm_so_iovec  *wr_vector=NULL;
    cvmx_buf_ptr_t    ptr; 
    int               wr_iovec_count = 0;
    int               size = 1;
    int               i;

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "%s: begins for socket: %d\n", __FUNCTION__, fd);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    wr_vector = vector = NULL;

    /* Zero-copy read */
    len = cvm_so_read_zc (fd, &vector);
    
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
	    sockets->sock[index].fd = 0;
	    sockets->free_count++;
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
	    sockets->sock[index].fd = 0;
	    sockets->free_count++;
   	    cvm_so_close(fd);
            return (error);
	}
    }

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "++ %d iovecs of data received (fd = %d) ++\n", 
             vector->iovec_count, fd);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

    /* this will process and free the iovec */
    process_read_iovec (vector);

    // send same size we got from the peer
    size = len;

    /* Allocate a new zero-copy iovec to echo back the received data */
    error = cvm_so_alloc_zc_iovec (&wr_vector, size);

    if (error < 0)
    {
	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "%s: Failed to allocate iovec\n", __FUNCTION__);
	return 0;
    }

    /* populate data */
    for (i=0; i<wr_vector->iovec_count; i++)
    {
        ptr = (cvmx_buf_ptr_t) wr_vector->iovec_ptr_array[i].iov_base;
        memset ( CASTPTR(char,ptr.s.addr), 0x9f, wr_vector->iovec_ptr_array[i].iov_len);
    }

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "%s: zero-copy send of %d bytes (%d iovecs)\n", 
                        __FUNCTION__, size, wr_vector->iovec_count);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

    wr_iovec_count = wr_vector->iovec_count;

do_writezc_again:
    /* Zero-copy write */
    error = cvm_so_write_zc (fd, wr_vector, 1);
    if (0>error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "%s: cvm_so_write_zc failed (error = 0x%X)\n", __FUNCTION__, errno); 
        CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "===============================================\n");
	if (errno == CVM_COMMON_EAGAIN)
	{
	    goto do_writezc_again;
	}
	else
	{
	    cvm_so_free_zc_iovec (wr_vector);
	    sockets->sock[index].fd = 0;
	    sockets->free_count++;
   	    cvm_so_close(fd);
            return (error);
	}
    } 

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "++ %d iovecs of data %d bytes sent (fd = %d) ++\n", 
                        wr_iovec_count, size, fd);
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_7, "===============================================\n");

    return 0;
}

int deal_with_data_zc (sockets_t* sockets, int index)
{
    int ret=-1;
#ifndef APP_OCTEON_2_OCTEON
    ret = deal_with_data_zcopy (sockets, index);
    /* ret = deal_with_data_zc_reuse_iovec (sockets, index); */
#else
    ret = deal_with_data_zc_verify (sockets, index);
#endif
    return (ret);
}


#endif

int process_read(cvm_so_status* list, int nfds, sockets_t* sockets)
{
    int i = 0;

    //CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_8, "++ select reports socket(s) are ready for read ++\n");

    for (i=0; i<nfds; i++)
    {
        if (list[i].read_ready)
	{
#ifdef APP_ECHO_SERVER_TCP_v4_v6
	    if (i==0 || i==1)  
	    {
		deal_with_new_connection(sockets, i);
	    }
#else
	    if (i==0)    deal_with_new_connection(sockets, i);
#endif

#ifndef USE_ZERO_COPY
            else         deal_with_data(sockets, list[i].reserved);
#else
            else         deal_with_data_zc (sockets, list[i].reserved);
#endif
	}
    }

    return (0);
}



#ifdef INET6

#ifdef APP_ECHO_SERVER_TCP_v4_v6
int echo_server_application_v4_v6 ()
{
    sockets_t sockets;
    int error = 0;
    int backlog_value = HEADSOCK_BACKLOG;
    int i=0;
    int core_id = -1;
    int no_of_fds_to_poll = 0;

#if defined(CVM_UDP_ECHO_SERVER)
    udp_echo_server_application();
    return (0);
#endif

    core_id = cvmx_get_core_num();

    /* do all the initializations */
    memset( (void*)&sockets, 0x0, sizeof(sockets_t) );
    sockets.free_count = MAX_SOCKETS;

    printf ("creating socket\n");

    /* slot zero will always be used by the listening socket */
    sockets.sock[0].fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
    if (sockets.sock[0].fd < 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to create a listening socket [error = 0x%X]\n", errno);
        return (0);
    }
    sockets.free_count--;

    for (i=0; i<MAX_ACCEPT_MULTI; i++) single_accept[i].addrlen = sizeof(struct cvm_ip_sockaddr_in);

    /* set the listening socket as non-blocking */
    sockets.sock[0].mode = FNONBIO;
    cvm_so_fcntl(sockets.sock[0].fd, sockets.sock[0].mode, 1);

    /* setup the bind info */
    sockets.sock[0].addr.sin_family = CVM_SO_AF_INET;
    sockets.sock[0].addr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
    sockets.sock[0].addr.sin_port = (80+core_id);
    sockets.sock[0].addr.sin_len = sizeof(sockets.sock[0].addr);

    error = cvm_so_bind(sockets.sock[0].fd, (struct cvm_so_sockaddr*)&sockets.sock[0].addr, sizeof(struct cvm_so_sockaddr));
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to bind new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[0].fd);
        return (0);
    }

    error = cvm_so_listen(sockets.sock[0].fd, backlog_value);
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to listen on a new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[0].fd);
        return (0);
    }    /* set the listening socket as non-blocking */

    printf ("%s: Socket %d configured for INET \n", __FUNCTION__, sockets.sock[0].fd);

    /* Setup for INET6 socket */

    /* slot zero will always be used by the listening socket */
    sockets.sock[1].fd = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
    if (sockets.sock[1].fd < 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to create a listening socket [error = 0x%X]\n", errno);
        return (0);
    }
    sockets.free_count--;


    /* set the listening socket as non-blocking */
    sockets.sock[1].mode = FNONBIO;
    cvm_so_fcntl(sockets.sock[1].fd, sockets.sock[1].mode, 1);

    memset (&sockets.sock[1].addr6, '\0', sizeof (sockets.sock[1].addr6));

    /* setup the bind info */
    sockets.sock[1].addr6.addr6_in6.sin6_family = CVM_SO_AF_INET6;
    sockets.sock[1].addr6.addr6_in6.sin6_addr = cvm_ip6_in6addr_any;
    sockets.sock[1].addr6.addr6_in6.sin6_port = (80+core_id);
    sockets.sock[1].addr6.addr6_in6.sin6_len = sizeof(sockets.sock[1].addr6);

    error = cvm_so_bind(sockets.sock[1].fd, (struct cvm_so_sockaddr *)&sockets.sock[1].addr6.addr6_in6, sizeof(struct cvm_so_sockaddr));
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to bind new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[1].fd);
        return (0);
    }

    error = cvm_so_listen(sockets.sock[1].fd, backlog_value);
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to listen on a new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[1].fd);
        return (0);
    }

    printf ("%s: Socket %d configured for INET6 \n", __FUNCTION__, sockets.sock[1].fd);
#ifdef IPERF_SERVER
    printf("--------------------------------------\n");
    printf("Server listening on TCP port (INET4) %d\n", sockets.sock[0].addr->sin_port);
    printf("Server listening on TCP port (INET6) %d\n", sockets.sock[1].addr->sin_port);
    printf("--------------------------------------\n");
#endif

    while(1)
    {
        no_of_fds_to_poll = build_poll_list(&sock_status[0], &sockets, MAX_SOCKETS);

        error = cvm_so_poll(no_of_fds_to_poll, &sock_status[0], (struct timeval*)0);
	if (error < 0)
	{
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : poll failed [error = 0x%X]\n", errno);
	    return (0);
	}

	if (error == 0)
	{
	    /* nothing read - should never happen when the timeout value of poll is 0 */
            //CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_app_loop : nothing is ready yet\n");
	}
	else
	{
	    //simprintf ("echo_App poll ret: %lld\n", error);
	    process_read(&sock_status[0], no_of_fds_to_poll, &sockets);
	}
    }

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "init app loop is now terminating\n");

    return 0;
}

#else /* APP_ECHO_SERVER_TCP_v4_v6 */

int echo_server_application ()
{
    sockets_t sockets;
    int error = 0;
    int backlog_value = HEADSOCK_BACKLOG;
    int i=0;
    int core_id = -1;
    int no_of_fds_to_poll = 0;

#if defined(CVM_UDP_ECHO_SERVER)
    udp_echo_server_application();
    return (0);
#endif

    core_id = cvmx_get_core_num();

    /* do all the initializations */
    memset( (void*)&sockets, 0x0, sizeof(sockets_t) );
    sockets.free_count = MAX_SOCKETS;

    printf ("creating socket\n");
    for (i=0; i<MAX_ACCEPT_MULTI; i++) single_accept[i].addrlen = sizeof(struct cvm_ip_sockaddr_in);

    /* slot zero will always be used by the listening socket */
    sockets.sock[0].fd = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
    if (sockets.sock[0].fd < 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to create a listening socket [error = 0x%X]\n", errno);
        return (0);
    }
    sockets.free_count--;


    /* set the listening socket as non-blocking */
    sockets.sock[0].mode = FNONBIO;
    cvm_so_fcntl(sockets.sock[0].fd, sockets.sock[0].mode, 1);

    memset (&sockets.sock[0].addr6, '\0', sizeof (sockets.sock[0].addr6));

    /* setup the bind info */
    sockets.sock[0].addr6.addr6_in6.sin6_family = CVM_SO_AF_INET6;
    sockets.sock[0].addr6.addr6_in6.sin6_addr = cvm_ip6_in6addr_any;
    sockets.sock[0].addr6.addr6_in6.sin6_port = (80+core_id);
    sockets.sock[0].addr6.addr6_in6.sin6_len = sizeof(sockets.sock[0].addr6);

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, "%s: socket created: %d addr: %s\n", 
              __FUNCTION__, sockets.sock[0].fd, 
	      cvm_ip6_ip6_sprintf (&sockets.sock[0].addr6.addr6_in6.sin6_addr));

    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, "sizeof cvm_so_sockaddr_storage %llu cvm_so_sockaddr %llu\n",
		       CAST64(sizeof (struct cvm_so_sockaddr_storage)),
	 	       CAST64(sizeof (struct cvm_so_sockaddr)));

    error = cvm_so_bind(sockets.sock[0].fd, (struct cvm_so_sockaddr *)&sockets.sock[0].addr6.addr6_in6, sizeof(struct cvm_so_sockaddr));
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to bind new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[0].fd);
        return (0);
    }
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, "%s: socket bind done: %d\n", __FUNCTION__, sockets.sock[0].fd);

    error = cvm_so_listen(sockets.sock[0].fd, backlog_value);
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to listen on a new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[0].fd);
        return (0);
    }
    CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_5, "%s: socket listen done: %d\n", __FUNCTION__, sockets.sock[0].fd);

#ifdef IPERF_SERVER
    printf("--------------------------------------\n");
    printf("Server listening on TCP port %d\n", sockets.sock[0].addr->sin_port);
    printf("--------------------------------------\n");
#endif

    while(1)
    {
        no_of_fds_to_poll = build_poll_list(&sock_status[0], &sockets, MAX_SOCKETS);

        error = cvm_so_poll(no_of_fds_to_poll, &sock_status[0], (struct timeval*)0);
	if (error < 0)
	{
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : poll failed [error = 0x%X]\n", errno);
	    return (0);
	}

	if (error == 0)
	{
	    /* nothing read - should never happen when the timeout value of poll is 0 */
            //CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_app_loop : nothing is ready yet\n");
	}
	else
	{
	    //simprintf ("echo_App poll ret: %lld\n", error);
	    //DBG_MSG ("poll returned ret: %lld\n", error);
	    process_read(&sock_status[0], no_of_fds_to_poll, &sockets);
	}
    }

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "init app loop is now terminating\n");

    return 0;
}

#endif /* APP_ECHO_SERVER_TCP_v4_v6 */

#else /* INET6 */

int echo_server_application()
{
    sockets_t sockets;
    int error = 0;
    int backlog_value = HEADSOCK_BACKLOG;
    int i=0;
    int core_id = -1;
    int no_of_fds_to_poll = 0;

#if defined(CVM_UDP_ECHO_SERVER)
    udp_echo_server_application();
    return (0);
#endif

    core_id = cvmx_get_core_num();

    /* do all the initializations */
    memset( (void*)&sockets, 0x0, sizeof(sockets_t) );
    sockets.free_count = MAX_SOCKETS;

    for (i=0; i<MAX_ACCEPT_MULTI; i++) single_accept[i].addrlen = sizeof(struct cvm_ip_sockaddr_in);

    /* slot zero will always be used by the listening socket */
    sockets.sock[0].fd = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_STREAM, CVM_IP_IPPROTO_TCP);
    if (sockets.sock[0].fd < 0)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to create a listening socket [error = 0x%X]\n", errno);
        return (0);
    }
    sockets.free_count--;


    /* set the listening socket as non-blocking */
    sockets.sock[0].mode = FNONBIO;
    cvm_so_fcntl(sockets.sock[0].fd, sockets.sock[0].mode, 1);

    /* setup the bind info */
    sockets.sock[0].addr.sin_family = CVM_SO_AF_INET;
    sockets.sock[0].addr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
    sockets.sock[0].addr.sin_port = (80+core_id);
    sockets.sock[0].addr.sin_len = sizeof(sockets.sock[0].addr);

    error = cvm_so_bind(sockets.sock[0].fd, (struct cvm_so_sockaddr*)&sockets.sock[0].addr, sizeof(struct cvm_so_sockaddr));
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to bind new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[0].fd);
        return (0);
    }

    error = cvm_so_listen(sockets.sock[0].fd, backlog_value);
    if (error)
    {
        CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : unable to listen on a new listening socket [error = 0x%X]\n", errno);
	cvm_so_close(sockets.sock[0].fd);
        return (0);
    }

#ifdef IPERF_SERVER
    printf("--------------------------------------\n");
    printf("Server listening on TCP port %d\n", sockets.sock[0].addr.sin_port);
    printf("--------------------------------------\n");
#endif

    while(1)
    {
        no_of_fds_to_poll = build_poll_list(&sock_status[0], &sockets, MAX_SOCKETS);

        error = cvm_so_poll(no_of_fds_to_poll, &sock_status[0], (struct timeval*)0);
	if (error < 0)
	{
            CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_ERROR, "inic_app_loop : poll failed [error = 0x%X]\n", errno);
	    return (0);
	}

	if (error == 0)
	{
	    /* nothing read - should never happen when the timeout value of poll is 0 */
            //CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_app_loop : nothing is ready yet\n");
	}
	else
	{
	    //simprintf ("echo_App poll ret: %lld\n", error);
	    process_read(&sock_status[0], no_of_fds_to_poll, &sockets);
	}
    }

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "init app loop is now terminating\n");

    return 0;
}
#endif /* INET6 */


#if defined(CVM_UDP_ECHO_SERVER)

int udp_do_data(int socket, int isv6)
{
    int  error = 0;
    char buffer[DATA_BUFFER_SIZE*2];

    struct cvm_ip_sockaddr_in faddr;

    void* other_addr = NULL;
    int other_addr_len = 0;

    int recv_data_size = 0;
    int len = 0;

#ifdef INET6
    struct cvm_ip6_sockaddr_in6 faddr6;
#endif


#ifdef INET6
    if (isv6)
    {
	other_addr = (void*)&faddr6;
	other_addr_len = sizeof(struct cvm_ip6_sockaddr_in6);
    }
    else
#endif
    {
	other_addr = (void*)&faddr;
	other_addr_len = sizeof(struct cvm_so_sockaddr);
    }

    recv_data_size = DATA_BUFFER_SIZE;


    /* receive data */
    len = cvm_so_recvfrom(socket, (void*)buffer, recv_data_size, 0, (struct cvm_so_sockaddr*)other_addr, (cvm_so_socklen_t*)&other_addr_len);
    if (len == -1)
    {
	if (errno == CVM_COMMON_EAGAIN)
	{
	    /* no data is available; return */
	    return (0);
	}

        printf("%s : recv on fd %d failed (error = 0x%X)\n", __FUNCTION__, socket, errno);
        return (error);
    }

    /* sned the same data back */
    error = cvm_so_sendto(socket, (void*)buffer, len, 0, (struct cvm_so_sockaddr*)other_addr, other_addr_len);
    if (error == -1)
    {
        printf("%s : send on fd %d failed (error = 0x%X)\n", __FUNCTION__, socket, errno); 
        return (error);
    }

    return (0);
}

int udp_echo_server_application(void)
{
    int error = 0;
    int core_id = -1;
    int mode;

    int udp_socket_v4 = 0;
    struct cvm_ip_sockaddr_in local_addr;

#ifdef INET6
    int udp_socket_v6 = 0;
    struct cvm_ip6_sockaddr_in6 local_addr6;
#endif

    printf("Starting UDP echo server ...\n");

    core_id = cvmx_get_core_num();

    /* create two udp sockets */
    udp_socket_v4 = cvm_so_socket(CVM_SO_AF_INET, CVM_SO_SOCK_DGRAM, CVM_IP_IPPROTO_UDP);
    if (udp_socket_v4 < 0)
    {
        printf("%s : unable to create v4 udp socket [error = 0x%X]\n", __FUNCTION__, errno);
        return (0);
    }
    printf("Udp socket %d created for IPv4\n", udp_socket_v4);

#ifdef INET6
    udp_socket_v6 = cvm_so_socket(CVM_SO_AF_INET6, CVM_SO_SOCK_DGRAM, CVM_IP_IPPROTO_UDP);
    if (udp_socket_v4 < 0)
    {
        printf("%s : unable to create v6 udp socket [error = 0x%X]\n", __FUNCTION__, errno);
        return (0);
    }
    printf("Udp socket %d created for IPv6\n", udp_socket_v6);
#endif

    /* bind the two sockets */
    local_addr.sin_family = CVM_SO_AF_INET;
    local_addr.sin_addr.s_addr = CVM_IP_INADDR_ANY;
    local_addr.sin_port = (8888+core_id);
    local_addr.sin_len = sizeof(local_addr);

    error = cvm_so_bind(udp_socket_v4, (struct cvm_so_sockaddr*)&local_addr, sizeof(struct cvm_so_sockaddr));
    if (error)
    {
        printf("%s : unable to bind v4 udp socket [error = 0x%X]\n", __FUNCTION__, errno);
	goto end_udp_server;
    }
    printf("%s: IPv4 UDP socket bound to port=%d, addr=0x%llx\n", __FUNCTION__, local_addr.sin_port, CAST64(local_addr.sin_addr.s_addr));

#ifdef INET6
    local_addr6.sin6_family = CVM_SO_AF_INET6;
    local_addr6.sin6_addr = cvm_ip6_in6addr_any;
    local_addr6.sin6_port = (9999+core_id);
    local_addr6.sin6_len = sizeof(local_addr6);

    error = cvm_so_bind(udp_socket_v6, (struct cvm_so_sockaddr*)&local_addr6, sizeof(struct cvm_ip6_sockaddr_in6));
    if (error)
    {
        printf("%s : unable to bind v6 udp socket [error = 0x%X]\n", __FUNCTION__, errno);
	goto end_udp_server;
    }
    printf("%s: IPv6 UDP socket bound to port=%d, addr=%s\n", __FUNCTION__, local_addr6.sin6_port, cvm_ip6_ip6_sprintf(&local_addr6.sin6_addr));
#endif

    /* set the two sockets non-blocking */
    mode = FNONBIO;
    cvm_so_fcntl(udp_socket_v4, mode, 1);
#ifdef INET6
    cvm_so_fcntl(udp_socket_v6, mode, 1);
#endif


    while(1)
    {
        error = udp_do_data(udp_socket_v4, 0);
	if (error) goto end_udp_server;

#ifdef INET6
        error = udp_do_data(udp_socket_v6, 1);
	if (error) goto end_udp_server;
#endif
    }


end_udp_server:
    cvm_so_close(udp_socket_v4);
#ifdef INET6
    cvm_so_close(udp_socket_v6);
#endif

    return (0);

}

#endif /* CVM_UDP_ECHO_SERVER */
