#ifndef __SCSI_LIB_H__
#define __SCSI_LIB_H__

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

int scsi_execute_req(struct Scsi_Host *shost, struct scsi_device *sdev, const unsigned char *cmd,
                     int data_direction, void *buffer, unsigned bufflen,
                     struct scsi_sense_hdr *sshdr, int timeout, int retries, uint64_t block);

int scsi_device_set_state(struct scsi_device *sdev, enum scsi_device_state state);

void scsi_request_fn_work(struct Scsi_Host *shost, struct scsi_device *sdev, cvmx_wqe_t * work);
#endif
