#include <stdio.h>
#include <stdlib.h>

#include "iSCSI-iface.h"
#include "initiator.h"

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

#include "cvmx-config.h"
#include "global-config.h"
#include "hosts.h"

cvmx_wqe_t * Get_Work(uint16_t cmd, uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group)
{
	cvmx_wqe_t * work = (cvmx_wqe_t *) cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_WQE_POOL);
        if(work == NULL)
                return NULL;

        memset(work, 0, sizeof(cvmx_wqe_t));

        work->unused = cmd;
        work->grp = ISCSI_GRP;
        work->tag_type = CVMX_POW_TAG_TYPE_ATOMIC;
        work->tag = ISCSI_TAG_BASE;

        iSCSI_Params * params_ptr = (iSCSI_Params *) work->packet_data;
        params_ptr->cmd.cmd_type = cmd;
	params_ptr->cmd.lun = lun;
	params_ptr->cmd.start_sector = start_sector;
	params_ptr->cmd.byte_size = byte_size;
	params_ptr->cmd.context = context;
	params_ptr->cmd.group = group;
	params_ptr->data_head = data_head;

	//if(data_head != NULL)
	//	memcpy(&(params_ptr->data_head), data_head, sizeof(data_list_t));	

	return work;
}
//Renjs
/*
int64_t iSCSI_Initialize(uint64_t context, uint64_t group)
{
	cvmx_wqe_t * work = Get_Work(iscsi_Initializae, 0, 0, 0, NULL, context, group);
	if(work == NULL)
	{
		printf("[iSCSI API]Can not alloc work!\n");
		return -1;
	}

#ifdef SEND_WORK_IFACE	
	cvmx_pow_work_submit(work, work->tag, work->tag_type, work->qos, work->grp);
#else
	//iSCSI_Login(work);
#endif
	return 0;
}
*/

int64_t iSCSI_Read_asyn(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group)
{
	cvmx_wqe_t * work = Get_Work(iscsi_Read_asyn, lun, start_sector, byte_size, data_head, context, group);
        if(work == NULL)                  
        {                                 
                printf("[iSCSI API]Can not alloc work!\n");
                return -1;
        }     

#ifdef SEND_WORK_IFACE
        cvmx_pow_work_submit(work, work->tag, work->tag_type, work->qos, work->grp);
#else
	scsi_read(work);
#endif
	return 0;
}
int numwin ;
int64_t iSCSI_Write_asyn(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group)
{
	//numwin++;
	cvmx_wqe_t * work = Get_Work(iscsi_Write_asyn, lun, start_sector, byte_size, data_head, context, group);
        if(work == NULL)                  
        {                                 
                printf("[iSCSI API]Can not alloc work!\n");
                return -1;
        }     

#ifdef SEND_WORK_IFACE
        cvmx_pow_work_submit(work, work->tag, work->tag_type, work->qos, work->grp);
#else
	scsi_write(work);
#endif
	return 0;
}
