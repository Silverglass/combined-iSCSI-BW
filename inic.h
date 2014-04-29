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

#ifndef __INIC_H__
#define __INIC_H__


int inic_generic_local_init(void);
int inic_data_global_init(void);
int inic_data_local_init(void);
int inic_app_global_init(void);
int inic_app_local_init(void);
int inic_data_loop(void);
int inic_app_loop(void);


/* echo server - default so don't need to put it within the #ifdef APP_ECHO_SERVER */
int echo_server_application(void);

#ifdef APP_ECHO_SERVER_MD
int echo_server_md_application(void);
#endif

#ifdef APP_CLIENT
int client_application(void);
#endif

#ifdef APP_SERVER_RAW
int server_application_raw(void);
#endif

#if defined INET6 && defined APP_ECHO_SERVER_TCP_v4_v6
int echo_server_application_v4_v6(void);
#endif

#ifdef DUTY_CYCLE
inline int inic_do_per_second_duty_cycle_processing(void);
#endif

/* few externs */
extern CVMX_SHARED uint64_t GET_response_pool0_buffer;
extern CVMX_SHARED uint64_t GET_response_pool0_size;
extern int core_id;
extern CVMX_SHARED cvmx_arena_list_t  main_arenas;


static inline void cvm_send_packet(void)
{
   cvmx_pko_command_word0_t pko_command;
   cvmx_buf_ptr_t  packet_ptr;
   uint64_t do_tag_switch=1;
   uint64_t port, queue;
   uint64_t prev_port=0;
   char first_packet=1;

   if(out_swp == NULL)
	return;

   //Add by gxy
   uint8_t * ptr;
   int i=0;

   if (out_swp->control.gth)
           ptr = ( cvmx_phys_to_ptr((*((cvmx_buf_ptr_t *) (cvmx_phys_to_ptr(out_swp->hw_wqe.packet_ptr.s.addr)))).s.addr) );
   else
           ptr = ( cvmx_phys_to_ptr(out_swp->hw_wqe.packet_ptr.s.addr));

#ifdef BOND

   if(ptr[13] == 6)//ARP
   {

          // printf("ARP!!!\n");
          // printf("ptr[41] mod 100 = %d \n", (ptr[41] % 100) );
          // printf("ptr[40] is %X, ptr[41] is %X \n", ptr[40], ptr[41] );

           if(ptr[41] % 100 == 7)
           {
                   out_swp->opprt = 7;
                   ptr[11] = ptr[27] = 7;
                   //printf("inic.h send_packet arp spi7\n");
           }
           if(ptr[41] % 100 == 8)
           {
                   out_swp->opprt = 8;
                   ptr[11] = ptr[27] = 8;

                   //printf("inic.h send_packet arp spi8\n");
           }
           
   }
   if(ptr[13] == 0)//IP
   {
           //printf("IP!!!\n");
           //printf("ptr[33] mod 100 = %d \n", (ptr[33] % 100) );

           if(ptr[33] % 100 == 7)
           {
                   out_swp->opprt = 7;
                   ptr[11] = 7;

                  // printf("inic.h send_packet ip spi7\n");
           }
           if(ptr[33] % 100 == 8)
           {
                   out_swp->opprt = 8;
                   ptr[11] = 8;
                   
                   //printf("inic.h send_packet ip spi8\n");
           }
           
   }
#endif

  // printf("\n----------------inic.h [%d], packet = ", out_swp->opprt );
   //for(i=0; i<out_swp->hw_wqe.packet_ptr.s.size; i++)
   //for(i=0; i< 54; i++)
    //       printf("%X ", ptr[i]);
   //printf("\n\n");

   port = out_swp->opprt;

   queue = cvmx_pko_get_base_queue(port);

   CVMX_SYNCIOBDMA;

   while(1)
   {
      cvm_common_wqe_t *tmp_swp;

      if (!first_packet)
      {
	if (port == prev_port) do_tag_switch = 0;
	else                   do_tag_switch = 1;
      }

      /*
       * Begin packet output by requesting a tag switch to atomic.
       * Write to a packet output queue must be synchronized across cores.
       */
      cvmx_pko_send_packet_prepare(port, queue, (do_tag_switch ? 1 : 0) );

      /* initialize pko command */
      pko_command.u64 = 0x0;
      pko_command.s.size0 = CVMX_FAU_OP_SIZE_64;
      pko_command.s.reg0 = CVM_FAU_PKO_OUTSTANDING;
      pko_command.s.subone0 = 1;

      if(out_swp->hw_wqe.word2.s.tcp_or_udp == 1)
      {
	 pko_command.s.ipoffp1 = out_swp->hw_wqe.word2.s.ip_offset + 1;
      }
      else
      {
	 pko_command.s.ipoffp1 = 0;
         CVM_COMMON_EXTRA_STATS_ADD64 (CVM_FAU_REG_NONTCPUDP_SENT, 1);
      }

#ifndef CVM_IP_FASTPATH // {
      /* Increment the total packet counts */
      cvmx_fau_atomic_add64(CVM_FAU_PKO_PACKETS, 1);
      cvmx_fau_atomic_add64(CVM_FAU_PKO_OUTSTANDING, 1);
#endif // CVM_IP_FASTPATH }

      /* Build a PKO pointer to this packet */
      pko_command.s.gather = out_swp->control.gth;
      pko_command.s.total_bytes = out_swp->hw_wqe.len;
      pko_command.s.ignore_i = 0;
      pko_command.s.dontfree = CVM_PKO_DONTFREE;
      packet_ptr = out_swp->hw_wqe.packet_ptr;

      if (out_swp->control.gth)
      {
	 pko_command.s.segs = packet_ptr.s.size = out_swp->hw_wqe.word2.s.bufs;
      }
      else
      {
	 pko_command.s.segs = out_swp->hw_wqe.word2.s.bufs;
      }

#ifdef TCP_DUMP
      if(out_swp->hw_wqe.word2.s.tcp_or_udp == 1)
      {
	  uint64_t ip_hdr = 0x0;

          if (out_swp->control.gth)
	      ip_hdr = CAST64( cvmx_phys_to_ptr((*((cvmx_buf_ptr_t *) (cvmx_phys_to_ptr(out_swp->hw_wqe.packet_ptr.s.addr)))).s.addr) );
          else
	      ip_hdr = CAST64( cvmx_phys_to_ptr(out_swp->hw_wqe.packet_ptr.s.addr));

	  ip_hdr += CVM_ENET_ETHER_HDR_LEN;

          CVM_TCP_TCP_DUMP ( (CASTPTR(void,ip_hdr)) );
      }
#endif


#ifdef SANITY_CHECKS // {
      cvm_common_output_sanity_and_buffer_count_update(out_swp, port);
#endif // SANITY_CHECKS }

      tmp_swp = out_swp;
      out_swp = out_swp->next;

      cvm_common_free_fpa_buffer(tmp_swp, CVMX_FPA_WQE_POOL, CVMX_FPA_WQE_POOL_SIZE / CVMX_CACHE_LINE_SIZE);

      /*
       * Send the packet and wait for the tag switch to complete before 
       * accessing the output queue. This ensures the locking required 
       * for the queue.
       *
       */
      if (cvmx_pko_send_packet_finish(port, queue, pko_command, packet_ptr, (do_tag_switch ? 1 : 0) ) )
      {
	 printf("Failed to send packet using cvmx_pko_send_packet_finish\n");
	 cvmx_fau_atomic_add64(CVM_FAU_PKO_ERRORS, 1);
      }

      CVM_COMMON_EXTRA_STATS_ADD64 (CVM_FAU_REG_PKTS_OUT, 1);

      if (out_swp == NULL)
	 break;

      if (first_packet) first_packet = 0;


      if (out_swp->control.gth)
              ptr = ( cvmx_phys_to_ptr((*((cvmx_buf_ptr_t *) (cvmx_phys_to_ptr(out_swp->hw_wqe.packet_ptr.s.addr)))).s.addr) );
      else
              ptr = ( cvmx_phys_to_ptr(out_swp->hw_wqe.packet_ptr.s.addr));


#ifdef BOND
      if(ptr[13] == 6)//ARP
      {

             // printf("ARP!!!\n");
             // printf("ptr[41] mod 100 = %d \n", (ptr[41] % 100) );

              if(ptr[41] % 100 == 7)
              {
                      out_swp->opprt = 7;
                      ptr[11] = ptr[27] = 7;
                      
                   //printf("inic.h send_packet arp spi7\n");
              }
              if(ptr[41] % 100 == 8)
              {
                      out_swp->opprt = 8;
                      ptr[11] = ptr[27] = 8;

                   //printf("inic.h send_packet arp spi8\n");
              }
      }
      if(ptr[13] == 0)//IP
      {
              //printf("IP!!!\n");
              //printf("ptr[33] mod 100 = %d \n", (ptr[33] % 100) );

              if(ptr[33] % 100 == 7)
              {
                      out_swp->opprt = 7;
                      ptr[11] = 7;

                   //printf("inic.h send_packet ip spi7\n");
              }
              if(ptr[33] % 100 == 8)
              {
                      out_swp->opprt = 8;
                      ptr[11] = 8;

                   //printf("inic.h send_packet ip spi8\n");
              }
      }
#endif

     // printf("\ninic.h [%d], packet = \n", out_swp->opprt );
     // for(i=0; i<54; i++)
      //        printf("%X ",  ptr[i]);
      //printf("\n\n");

      prev_port = port;
      port = out_swp->opprt;
      CVM_COMMON_KASSERT( (port<36), ("cvm_send_packet : invalid port number") );

      queue = cvmx_pko_get_base_queue(port);
   }
}


static inline void cvm_update_l4_offset_prot(cvm_common_wqe_t *swp)
{
    if (!swp->hw_wqe.word2.s.is_v6)
    {
        cvm_ip_ip_t *ih = ((cvm_ip_ip_t *)&(swp->hw_wqe.packet_data[CVM_COMMON_PD_ALIGN]));
        swp->l4_offset = ((uint16_t)(ih->ip_hl) << 2) + CVM_COMMON_PD_ALIGN;
        swp->l4_prot = ih->ip_p;
    }
#ifdef INET6
    else
    {
        struct cvm_ip6_ip6_hdr *ip6 = (struct cvm_ip6_ip6_hdr *) &swp->hw_wqe.packet_data[CVM_COMMON_IP6_PD_ALIGN];
        swp->l4_offset = CVM_IP6_IP6_HDRLEN;
        swp->l4_prot = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    }
#endif

    return;
}


/*
 * Few DNI mode related support macros
 */
#if defined(CVM_COMBINED_APP_STACK)
#define INIC_DECLARE_HSOCKET() cvm_so_hsocket_t *hsocket = NULL;
#define INIC_GET_HSOCKET_FROM_TIMER_WQE(swp, hsocket, app_tag, app_tag_type)	\
{ \
    tcp_int_payload_t *tip = (tcp_int_payload_t *)&(swp->hw_wqe.packet_data[0]); \
    cvm_tcp_tcpcb_t *tcpcb =NULL; \
    hsocket = NULL; \
    if (tip) tcpcb = tip->tcb; \
    if (tcpcb) \
    { \
        if (tcpcb->signature == tip->signature) \
        { \
            hsocket = cvm_so_get_handle_from_fd (tcpcb->shim_info.fd); \
            app_tag = swp->hw_wqe.tag; \
            app_tag_type = swp->hw_wqe.tag_type; \
	} \
    } \
}

#define INIC_DO_DNI_EVENTS(hsocket, app_tag, app_tag_type)	\
{ \
    if (hsocket) \
    { \
        uint32_t events = cvm_so_process_app(hsocket); \
        if (events)  \
        { \
            CVMX_SYNCWS; \
            cvmx_pow_tag_sw_null (); \
            cvm_so_notify_app (hsocket, events); \
            cvmx_pow_tag_sw_full (NULL, app_tag, app_tag_type, 0); \
            cvmx_pow_tag_sw_wait (); \
        } \
    } \
}
#else
#define INIC_DECLARE_HSOCKET()
#define INIC_GET_HSOCKET_FROM_TIMER_WQE(swp, hsocket, app_tag, app_tag_type)
#define INIC_DO_DNI_EVENTS(hsocket, app_tag, app_tag_type)
#endif

#endif /* __INIC_H__ */
