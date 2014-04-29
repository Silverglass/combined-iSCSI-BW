#ifndef __SCSI_HOST__
#define __SCSI_HOST__ 

#include "iSCSI-typedefs.h"

#include "cvmx.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-spinlock.h"
#include "cvmx-malloc.h"
#include "cvmx-coremask.h"
#include "cvmx-sysinfo.h"


int64_t scsi_read(cvmx_wqe_t * work);
//int64_t scsi_read(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group);

int64_t scsi_write(cvmx_wqe_t * work);
//int64_t scsi_write(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group);


#endif
