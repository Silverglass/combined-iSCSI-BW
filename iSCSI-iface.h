#ifndef __ISCSI_IFACE_H__
#define __ISCSI_IFACE_H__

#include "iSCSI-typedefs.h"
//Renjs
//int64_t iSCSI_Initialize(uint64_t context, uint64_t group);

int64_t iSCSI_Read_asyn(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group);

int64_t iSCSI_Write_asyn(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group);

#endif
