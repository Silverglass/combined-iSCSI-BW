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
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "cvmx-config.h"
#include "global-config.h"

#include "cvmx.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-spinlock.h"
#include "cvmx-helper.h"
#include "cvmx-malloc.h"

#include "socket.h"
#include "cvm-ip-in.h"
#include "cvm-ip.h"
#include "cvm-ip-if-var.h"

#ifdef INET6
#include "cvm-in6.h"
#include "cvm-in6-var.h"
#include "cvm-ip6.h"
#endif

#include "inic.h"

#include "initiator.h"
#include "config.h"
#include "hosts.h"

#include "socketvar.h"

#include "cvm-tcp-var.h"

#include "cvm-socket.h"
#ifdef ANVL_OCTEON_PORT
#include "mntcpapp.h"
#endif

#define RAND_VAL   0x53

int inic_app_local_init(void)
{
    int core_id = -1;

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_app_local_init\n");

    core_id = cvmx_get_core_num();

    /* 
     * for each core running the application, seed
     * the random number generator
     */

    srand((core_id+1) * RAND_VAL);

    if ( (cvmx_helper_initialize_packet_io_local()) == -1)
    {
        printf("inic_app_local_init : Failed to initialize/setup input ports\n");
        return (-1);
    }

    cvm_so_app_socket_local_init();

    return (0);
}


int inic_app_global_init(void)
{

    CVM_COMMON_DBG_MSG(CVM_COMMON_DBG_LVL_INFO, "inic_app_global_init\n");

    cvm_so_app_socket_global_init();

    CVMX_SYNCWS;

    return (0);
}

/* inic application loop */
int inic_app_loop()
{
  	uint64_t ipaddr;
   	int ret, res;
	char scsi_buffer[4096];

  	ipaddr = 0xc0a80165;

   	node_rec_t *rec;
	rec = malloc(sizeof(struct node_rec));
    	//ret = session_login_task(rec); 
	printf("inic_app_loop: session_login_task ret = %d\n", ret);	
	if(ret == 0)
		printf("\n\n\n\n\ninic_app_loop: iSCSI Login succeed !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n\n\n\n\n\n\n\n\n");
	
	free(rec);





	int i=0;
	for(i=0; i<4096; i++)
	{
		if(i%3 ==0)
			scsi_buffer[i] = 'a';
		else
			scsi_buffer[i] = 'b';
	}

	uint64_t cycle1, cycle2, time; 

	cycle1 = cvmx_get_cycle();

	unsigned long count = 0;
	//count = (97000000-1000000)*512/4096;
	count = 4000;
	unsigned long offset = 0;
	
	for(offset=0; offset<count; offset++)
	{
		//res = scsi_write(0, (void *)scsi_buffer, 4096, (1000000 + offset*4096) );
		if(res !=0)
			break;
	}
	
	printf("inic_app_loop: scsi_write() done, res = %d \n", res);

	cycle2 = cvmx_get_cycle();

	time = (cycle2-cycle1)/800000;

	printf("inic_app_loop: Writen %lld B data to LUN, time = %lld ms\n\n", count*4096, time);



#ifdef WRITE
	uint64_t cycle1, cycle2, time; 
	cycle1 = cvmx_get_cycle();
	unsigned long count = 0;

	count = 2000;
	unsigned long offset = 0;
	
	for(offset=0; offset<count; offset++)
	{
		//res = scsi_read(0, (void *)scsi_buffer, 4096, (1000000 + offset*4096) );
		//res = scsi_read(0, (void *)scsi_buffer, 4096, 1000000);
		res = scsi_read(0, (void *)scsi_buffer, 4096, (1000000 + rand()%40960) );
		if(res !=0)
		{
			printf("inic_app_loop: scsi_read failed at count = %d \n", count );
			break;
		}
	}

	printf("inic_app_loop: scsi_read() done, res = %d \n", res);

	cycle2 = cvmx_get_cycle();

	time = (cycle2-cycle1)/800000;

	printf("inic_app_loop: Read %lld B data to LUN, time = %lld ms\n\n", count*4096, time);
#endif


	/*
	res = scsi_read(0, (void *)scsi_buffer, 4096, 4000000);

	printf("inic_app_loop: scsi_read() done, res = %d \n\n", res);

	i=0;
	printf("inic_app_loop: scsi_read() done, scsi_buffer = 0x");
	for(i=0; i<4096; i++)
	{
		printf("%c ", scsi_buffer[i]);
	}
	printf("\n\n");
	*/

	while(1);

#ifdef APP_ECHO_SERVER
    /* echo server */
    echo_server_application();

#elif defined IPERF_SERVER
    echo_server_application();

#elif defined APP_CLIENT

#ifndef APP_OCTEON_2_OCTEON
    /* client */
    client_application();
#else
    /* client app for back-to-back octeons */
    client_application_rcv_only_zc_verify();
#endif

#elif defined APP_SERVER_RAW
    server_application_raw();

#elif defined APP_TCP_ANVL_STUB
    CVM_COMMON_SIMPRINTF ("Starting TCP ANVL Stub application\n");
    anvl_stub_app ();
#elif defined APP_ECHO_SERVER_MD
    echo_server_md_application();
#elif defined (INET6) && defined (APP_ECHO_SERVER_TCP_v4_v6)
    echo_server_application_v4_v6();
#else
    /* default */
    echo_server_application();
#endif

    printf("Application core %lld exited..\n", CAST64(cvmx_get_core_num()) );

    while(1);

    return 0;
}
