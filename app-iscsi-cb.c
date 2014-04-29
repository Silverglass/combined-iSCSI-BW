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
#include "cvm-socket-cb.h"
#include "cvm-socket-raw.h"

#include "inic.h"

#include "app-iscsi-cb.h"
#include "iSCSI-typedefs.h"
#include "initiator.h"
#include "iscsi_tcp.h"

CVMX_SHARED uint64_t xxx = 0;

//Renjs
CVMX_SHARED cvmx_spinlock_t iscsilock[10];
CVMX_SHARED uint64_t nextlun = 0;
CVMX_SHARED uint64_t lunip[6];
CVMX_SHARED uint64_t init_group;
//#define MAX_LUN_NUMBER 5
#define TOTAL_LUN_NUMBER 1


//Renjs
CVMX_SHARED cvmx_spinlock_t mylock[TOTAL_LUN_NUMBER];
CVMX_SHARED uint64_t byte_recv = 0;
CVMX_SHARED uint64_t recv_time = 0;
CVMX_SHARED int64_t cc = 0;
CVMX_SHARED extern  uint64_t run = 0;
//Renjs
CVMX_SHARED uint64_t mycontext[TOTAL_LUN_NUMBER];
//CVMX_SHARED uint64_t mytime = 0;
uint64_t mytime = 0;
uint64_t writetime = 0;
int wi = 0;
CVMX_SHARED uint64_t recvtime = 0;
CVMX_SHARED uint64_t datatime = 0;
CVMX_SHARED uint64_t read_position[6];
CVMX_SHARED uint64_t write_position[6];
CVMX_SHARED int ctw = 0;
extern int numwin = 0 ;
int ittdec = 0;
int sss = 0;
//Renjs
int iSCSI_Initialize(uint64_t context, uint64_t group)
{	
	int i;
	for(i = 0;i < TOTAL_LUN_NUMBER; i++)
	{
		lunip[i] = 106 + i;
		cvmx_spinlock_init(&(mylock[i]));
	}
	
	//for(i = 0;i < 6; i++)
  init_group = group;
	iSCSI_Login();
  /*
	cvmx_wqe_t * work = (cvmx_wqe_t *) cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
	memset(work, 0, sizeof(cvmx_wqe_t));
	work->grp = ISCSI_GRP;
	work->tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
	work->tag = ISCSI_TAG_BASE;
	cvmx_pow_work_submit(work, work->tag, work->tag_type, work->qos, 10);
  */
  return 0;
}

int iscsi_recv (iSCSI_context * current_context1)
{
        uiscsi_conn_t *conn = current_context1->conn;
        int res;
        while(1)
        {
                uint64_t a = cvmx_get_cycle();
                struct scsi_cmnd *sc = NULL;
                if(run == 0)
                 res = kiscsi_tcp_data_recv((struct iscsi_conn *)(conn->handle), sc);
                else
                {
                //printf("  notification   tcp recv  run = 1\n");
                res = kiscsi_tcp_data_recv1((struct iscsi_conn *)(conn->handle), sc);
                //printf("notification after recv1 res = %d\n", res);
                }
                if(res < -1)
                        printf("iscsi_recv :res is %d,  xxx is %d cc is %d\n", res, xxx, cc);
                if(res <= 0)
                {
                        break;
                        printf("res = %d and break!\n", res);
                }
        }
        return 0;
}





int iSCSI_system_notification (uint32_t fd, void* context, uint32_t event_flags)
{
	int coreid = cvmx_get_core_num();
	int result = 0;
	iSCSI_context * current_context = (iSCSI_context *) (context);
	mycontext[current_context->lun] = context;
	uint32_t tag = ISCSI_TAG_BASE | current_context->socket_fd;
	
	if(fd != current_context->socket_fd)
	{
		printf("[iSCSI SYSTEM]socket fd does not match\n");
		return -1;
	}

	if(current_context->state != iSCSI_RUN)
		printf("context state is %d!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!,	event_flags is %d\n", current_context->state, event_flags);
	
	switch (event_flags) {
		case CVM_SO_CONN_ESTABLISHED:
			printf("TCP connectiong is established!!!!!!!!!!!!!!!!,	context state is %d context ip is %d\n ", current_context->state,current_context->ip);
			if(current_context->state == iSCSI_START_CONNECT) 
			{
				current_context->state = iSCSI_SEND_LOGIN_PDU; 
				result = session_login_send_login_pdu(current_context);				
			}
			else
			{
				result = -1;
			}
			break;
		case CVM_SO_CONN_ERROR:
			{
			}
			break;
		case CVM_SO_CAN_READ:
			if(current_context->state == iSCSI_SEND_LOGIN_PDU) 
			{
				if(cvmx_spinlock_trylock(&(mylock[current_context->lun])))
					return 0;
				printf("   current_context->state == iSCSI_SEND_LOGIN_PDU    context ip is %d\n ",current_context->ip);
				current_context->state = iSCSI_SEND_LOGIN_CMD;
				result = session_login_send_login_cmd(current_context);
				current_context->state = iSCSI_RUN;
				nextlun++;
				printf("CVM_SO_CAN_READ after nextlun++   nextlun is %d\n",nextlun);
				if(nextlun <= (TOTAL_LUN_NUMBER - 1))
              		iSCSI_Login();
              	else
              	{
					printf("%%%%%%%%%%%%%%%%nextlun = %d, let run = 1 \n ",nextlun);
					run = 1;
					cvmx_wqe_t * work = (cvmx_wqe_t *) cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
					iSCSI_DiskInfo * disk = (iSCSI_DiskInfo *) cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
					memset(work, 0, sizeof(cvmx_wqe_t));
					work->grp = init_group;
					work->tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
					work->tag = ISCSI_TAG_BASE;
					iSCSI_Init_Result * init_re = (iSCSI_Init_Result *) work->packet_data;
					init_re->initialize_status = 0;
					init_re->data_pool = CVMX_FPA_PACKET_POOL;
					init_re->disk_info = disk;
					disk->lun_num = 6;
					disk->sector_size = 512;
					cvmx_pow_work_submit(work, work->tag, work->tag_type, work->qos, init_group);
              	}
              cvmx_spinlock_unlock(&(mylock[current_context->lun]));
			}
			else if(current_context->state == iSCSI_SEND_LOGIN_CMD)
			{
				current_context->state = iSCSI_SEND_LOGIN_CMD;
				current_context->syn_among_core = 0;
			}
			else if(current_context->state == iSCSI_RUN)
			{
				if(cvmx_spinlock_trylock(&(mylock[current_context->lun])))
					return 0;      
        		iscsi_recv (current_context);
				cvmx_spinlock_unlock(&(mylock[current_context->lun]));
			}
			break;
		case CVM_SO_RX_CLOSE:
			{			
				printf("close\n");
			}
			break;	
	}
	return 0;
}


int cvm_register_dni_callback (void)
{
	int error = 0;

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

	do {

		if ((error = cvm_so_register_function ((void *) iscsi_init_global, CVM_SO_FNPTR_INIT_GLOBAL, 0))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_init_global failed\n");
			break;
		}

		if ((error = cvm_so_register_function ((void *) iscsi_init_local, CVM_SO_FNPTR_INIT_LOCAL, 0))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_init_local failed\n");
			break;
		}

		if ((error = cvm_so_register_function ((void *) iscsi_main_global, CVM_SO_FNPTR_MAIN_GLOBAL, 0))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_main_global failed\n");
			break;
		}

		if ((error = cvm_so_register_function ((void *) iscsi_main_local, CVM_SO_FNPTR_MAIN_LOCAL, 0))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_main_local failed\n");
			break;
		}

		if ((error = cvm_so_register_function ((void *) iscsi_timeout_handler, CVM_SO_FNPTR_TIMEOUT_HANDLER, 0xfffffff))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_timeout_handler failed\n");
			break;
		}

		if ((error = cvm_so_register_function ((void *) iscsi_notification, CVM_SO_FNPTR_NOTIFICATION, 0))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_notification failed\n");
			break;
		}

		if ((error = cvm_so_register_function ((void *) iscsi_exit_global, CVM_SO_FNPTR_EXIT_GLOBAL, 0))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_exit_global failed\n");
			break;
		}

		if ((error = cvm_so_register_function ((void *) iscsi_exit_local, CVM_SO_FNPTR_EXIT_LOCAL, 0))
				!= 0) {
			CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_ERROR, "registering iscsi_exit_local failed\n");
			break;
		}

	} while (0);

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

	return error;
}

int iscsi_init_global () {
	int error = 0;

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

	return error;
}

int iscsi_init_local () {
	int error = 0;

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

	return error;
}

int iscsi_main_global ()
{
	int error = 0;

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

	//Renjs
	 iSCSI_Initialize(10,10);
	//iSCSI_Login();

	//cvmx_spinlock_init(&mylock);

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

	return error;
}

int iscsi_main_local () {
	int error = 0;

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

	return error;
}

int numwin ;

int iscsi_timeout_handler () 
{
	if(run == 0)
		return 0;
	int culun = rand() % TOTAL_LUN_NUMBER;
	int error = 0;
	iSCSI_context * current_context = (iSCSI_context *) (mycontext[culun]);
	if(run == 1 && culun != current_context->lun)
		printf("culun != current_context->lun   \n");

	if(cvmx_get_cycle() - mytime > 8000000000)
	{
	    cvmx_pow_iq_com_cnt_t pow_iq_com_cnt;
	    pow_iq_com_cnt.u64 = cvmx_read_csr(CVMX_POW_IQ_COM_CNT);
	    printf("PAKCET:%llu,     WQE:%llu,   POW:%llu\n", cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(CVMX_FPA_PACKET_POOL)), cvmx_read_csr(CVMX_FPA_QUEX_AVAILABLE(CVMX_FPA_WQE_POOL)), pow_iq_com_cnt.s.iq_cnt);
	    if(run == 1)
	    {
	    	printf("current_context->itt_used is %d\n", current_context->itt_used);
	    }
	    mytime = cvmx_get_cycle();
	}
    if(cvmx_spinlock_trylock(&(mylock[culun])))
            return 0;

	if(run >= 1 && current_context->itt_used <= 5 && nextlun >= TOTAL_LUN_NUMBER )
	{

		uint64_t a = cvmx_get_cycle();
		int read_k = 170;
		int write_k = 15;

		int i, j;
		if(a - current_context->write_time < 45000)//45000 for 1 lun, 6 core.
			goto GOON;
		{
			
			data_list_t * data_head = NULL;
			data_list_t * temp_data_head = NULL;
			
			for(j=0;j<write_k;j++)
			{
				data_list_t * next_data_head = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
				next_data_head->data_ptr = cvmx_ptr_to_phys(cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL));
				next_data_head->data_pool = CVMX_FPA_PACKET_POOL;
				next_data_head->data_len = 2048;
				next_data_head->offset = 0;
				next_data_head->copied = next_data_head->offset;
				next_data_head->next = NULL;
				
				if(temp_data_head == NULL)
				{
					temp_data_head = next_data_head;
				}
				else
				{	
					temp_data_head->next = next_data_head;
					temp_data_head = next_data_head;
				}
				
				if(data_head == NULL)
					data_head = next_data_head;
			}

			write_position[culun] += (uint64_t)(write_k*4);
			//memset(cvmx_phys_to_ptr(data_head->data_ptr), xxx%8, 2048);
			//iSCSI_Read_asyn(0, (uint64_t)(position), 2048*k, data_head, 0x1234, 10);
			//iSCSI_Read_asyn(0, 100000 + 16*xxx, 8192, data_head, 0x1234, 10);
			//iSCSI_Read_asyn(0, 100000 + rand() % 10000, 1024, data_head, 0x1234, 10);
			iSCSI_Write_asyn(culun, write_position[culun], 2048*write_k, data_head, 0x1234, 10);
		}
GOON:
			
		{	
			data_list_t * data_head1 = NULL;
			data_list_t * temp_data_head1 = NULL;
			
			for(j=0;j<read_k;j++)
			{
				data_list_t * next_data_head = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
				next_data_head->data_ptr = cvmx_ptr_to_phys(cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL));
				next_data_head->data_pool = CVMX_FPA_PACKET_POOL;
				next_data_head->data_len = 2048;
				next_data_head->offset = 0;
				next_data_head->copied = next_data_head->offset;
				next_data_head->next = NULL;
				
				if(temp_data_head1== NULL)
				{
					temp_data_head1= next_data_head;
				}
				else
				{	
					temp_data_head1->next = next_data_head;
					temp_data_head1 = next_data_head;
				}
				
				if(data_head1== NULL)
					data_head1= next_data_head;
			}
			//read_position[culun] += (uint64_t)(read_k*4 + rand() % 200000);
			read_position[culun] += (uint64_t)(read_k*4 );
			iSCSI_Read_asyn(culun,read_position[culun] , 2048*read_k, data_head1, 0x1234, 10);		
		}
    
			xxx++;
	}
	cvmx_spinlock_unlock(&(mylock[culun]));
	return error;
	
}

/* TBD: event_flags can contain more than one flags */
int iscsi_notification (uint32_t fd, void* context, uint32_t event_flags)
{
	int error = 0;

	if(!context)
	{
		printf("Error notification fd =%d context=%lld\n",fd,context);
		return -1;
	}
	//printf("iscsi_notification get context is %llX\n", context);

	uint64_t * type_ptr = (uint64_t*)context;
	switch((*type_ptr))
	{
		case CONTEXT_TYPE_ISCSI_SYSTEM:
			//printf("context type is %d\n", CONTEXT_TYPE_ISCSI_SYSTEM);
			iSCSI_system_notification(fd, context, event_flags);
			break;

		default:
			printf("Error notification fd =%d context=%lld type=%lld\n",fd,context,(*type_ptr));
			break;
	}

	return error;
}

int iscsi_exit_global ()
{
	int error = 0;

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

	return error;
}

int iscsi_exit_local () {
	int error = 0;

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, ">>%s (void)\n", __FUNCTION__);

	CVM_COMMON_DBG_MSG (CVM_COMMON_DBG_LVL_INFO, "<<%s (return = %d)\n", __FUNCTION__, error);

	return error;
}


#endif
