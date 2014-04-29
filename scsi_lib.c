/*
 *  scsi_lib.c Copyright (C) 1999 Eric Youngdale
 *
 *  SCSI queueing library.
 *      Initial versions: Eric Youngdale (eric@andante.org).
 *                        Based upon conversations with large numbers
 *                        of people at Linux Expo.
 */

#include "device.h"
#include "scsi.h"

#include "iSCSI-typedefs.h"

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
int numwin;
/* Command group 3 is reserved and should never be used.  */
CVMX_SHARED const unsigned char scsi_command_size[8] =
{
        6, 10, 10, 12,
        16, 12, 10, 10
};

/**
 *	sd_init_command - build a scsi (read or write) command from
 *	information in the request structure.
 *	@SCpnt: pointer to mid-level's per scsi command structure that
 *	contains request and into which the scsi command is written
 *
 *	Returns 1 if successful and 0 if error (or cannot be done now).
 **/
static int sd_init_command(struct scsi_cmnd * SCpnt, const unsigned char *cmd_string, uint64_t block)
{
	struct scsi_device *sdp = SCpnt->device;
	unsigned int this_count = SCpnt->request_bufflen >> 9;
	//printf("++++++++++++++++++++++this_count is %d\n", this_count);



	//printf("sd_init_command1:  SCpnt->request_bufflen = %d\n",SCpnt->request_bufflen);

	/*
	 * If we have a 1K hardware sectorsize, prevent access to single
	 * 512 byte sectors.  In theory we could handle this - in fact
	 * the scsi cdrom driver must be able to handle this because
	 * we typically use 1K blocksizes, and cdroms typically have
	 * 2K hardware sectorsizes.  Of course, things are simpler
	 * with the cdrom, since it is read-only.  For performance
	 * reasons, the filesystems should be able to handle this
	 * and not force the scsi disk driver to use bounce buffers
	 * for this.
	 */
	if (strcmp(cmd_string, "write") == 0) {
		SCpnt->cmnd[0] = WRITE_6;
		SCpnt->sc_data_direction = DMA_TO_DEVICE;
	} else if (strcmp(cmd_string, "read") == 0) {
		SCpnt->cmnd[0] = READ_6;
		SCpnt->sc_data_direction = DMA_FROM_DEVICE;
	} else {
		printf("sd: Unknown command\n");
		return 0;
	}

	SCpnt->cmnd[1] = 0;

	if (block > 0xffffffff) {
		printf("block > 0xffffffff :%X\n", block);
		printf("block > 0xffffffff :%llX,	%llX\n", 0xffffffff, block);
		SCpnt->cmnd[0] += READ_16 - READ_6;
		SCpnt->cmnd[1] |= 0;
		SCpnt->cmnd[2] = sizeof(block) > 4 ? (unsigned char) (block >> 56) & 0xff : 0;
		SCpnt->cmnd[3] = sizeof(block) > 4 ? (unsigned char) (block >> 48) & 0xff : 0;
		SCpnt->cmnd[4] = sizeof(block) > 4 ? (unsigned char) (block >> 40) & 0xff : 0;
		SCpnt->cmnd[5] = sizeof(block) > 4 ? (unsigned char) (block >> 32) & 0xff : 0;
		SCpnt->cmnd[6] = (unsigned char) (block >> 24) & 0xff;
		SCpnt->cmnd[7] = (unsigned char) (block >> 16) & 0xff;
		SCpnt->cmnd[8] = (unsigned char) (block >> 8) & 0xff;
		SCpnt->cmnd[9] = (unsigned char) block & 0xff;
		SCpnt->cmnd[10] = (unsigned char) (this_count >> 24) & 0xff;
		SCpnt->cmnd[11] = (unsigned char) (this_count >> 16) & 0xff;
		SCpnt->cmnd[12] = (unsigned char) (this_count >> 8) & 0xff;
		SCpnt->cmnd[13] = (unsigned char) this_count & 0xff;
		SCpnt->cmnd[14] = SCpnt->cmnd[15] = 0;
	} else if ((this_count > 0xff) || (block > 0x1fffff) ||
		SCpnt->device->use_10_for_rw) {
		if (this_count > 0xffff)
			this_count = 0xffff;
		//printf("(this_count > 0xff) || (block > 0x1fffff) this_count:%X,	block:%X\n", this_count, block);

		SCpnt->cmnd[0] += READ_10 - READ_6;
		SCpnt->cmnd[1] |= 0;
		SCpnt->cmnd[2] = (unsigned char) (block >> 24) & 0xff;
		SCpnt->cmnd[3] = (unsigned char) (block >> 16) & 0xff;
		SCpnt->cmnd[4] = (unsigned char) (block >> 8) & 0xff;
		SCpnt->cmnd[5] = (unsigned char) block & 0xff;
		SCpnt->cmnd[6] = SCpnt->cmnd[9] = 0;
		SCpnt->cmnd[7] = (unsigned char) (this_count >> 8) & 0xff;
		SCpnt->cmnd[8] = (unsigned char) this_count & 0xff;
	} else {
		printf("block is %X,	this_count is %X\n", block, this_count);
		SCpnt->cmnd[1] |= (unsigned char) ((block >> 16) & 0x1f);
		SCpnt->cmnd[2] = (unsigned char) ((block >> 8) & 0xff);
		SCpnt->cmnd[3] = (unsigned char) block & 0xff;
		SCpnt->cmnd[4] = (unsigned char) this_count;
		SCpnt->cmnd[5] = 0;
	}

	//Renjs
	//SCpnt->request_bufflen = this_count * 512;

	//printf("sd_init_command2:  SCpnt->request_bufflen = %d\n",SCpnt->request_bufflen);
	/*
	 * We shouldn't disconnect in the middle of a sector, so with a dumb
	 * host adapter, it's safe to assume that we can at least transfer
	 * this many bytes between each connect / disconnect.
	 */
	SCpnt->transfersize = 512;
	SCpnt->underflow = this_count << 9;
	//SCpnt->allowed = SD_MAX_RETRIES;

	/*
	 * This is the completion routine we use.  This is matched in terms
	 * of capability to this function.
	 */
	//SCpnt->done = sd_rw_intr;

	/*
	 * This indicates that the command is ready from our end to be
	 * queued.
	 */
	return 1;
}

static void scsi_request_fn(struct Scsi_Host *shost, struct scsi_device *sdev, const unsigned char *cmd_string, enum dma_data_direction data_direction, void *buffer, unsigned bufflen, uint64_t block);

/**
 * scsi_execute - insert request and wait for the result
 * @sdev:	scsi device
 * @cmd:	scsi command
 * @data_direction: data direction
 * @buffer:	data buffer
 * @bufflen:	len of buffer
 * @sense:	optional sense buffer
 * @timeout:	request timeout in seconds
 * @retries:	number of times to retry request
 * @flags:	or into request flags;
 *
 * returns the req->errors value which is the the scsi_cmnd result
 * field.
 **/
int scsi_execute(struct Scsi_Host *shost, struct scsi_device *sdev, const unsigned char *cmd,
		 enum dma_data_direction data_direction, void *buffer, unsigned bufflen,
		 unsigned char *sense, int timeout, int retries, int flags, uint64_t block)
{
	//printf("scsi_execute\n");
	//int write = (data_direction == DMA_TO_DEVICE);
	
	//int ret = DRIVER_ERROR << 24;
	int ret = 0;

	int cmd_len = COMMAND_SIZE(cmd[0]);

	scsi_request_fn(shost, sdev, cmd, data_direction, buffer, bufflen, block);

	return ret;
}


/*static inline int scsi_sense_valid(struct scsi_sense_hdr *sshdr)
{
	if (!sshdr)
		return 0;

	return (sshdr->response_code & 0x70) == 0x70;
}*/



int scsi_normalize_sense(const uint8_t *sense_buffer, int sb_len,
                         struct scsi_sense_hdr *sshdr)
{
        if (!sense_buffer || !sb_len)
                return 0;

        memset(sshdr, 0, sizeof(struct scsi_sense_hdr));

        sshdr->response_code = (sense_buffer[0] & 0x7f);

        if (!scsi_sense_valid(sshdr))
                return 0;

        if (sshdr->response_code >= 0x72) {
                /*
                 * descriptor format
                 */
                if (sb_len > 1)
                        sshdr->sense_key = (sense_buffer[1] & 0xf);
                if (sb_len > 2)
                        sshdr->asc = sense_buffer[2];
                if (sb_len > 3)
                        sshdr->ascq = sense_buffer[3];
                if (sb_len > 7)
                        sshdr->additional_length = sense_buffer[7];
        } else {
                /* 
                 * fixed format
                 */
                if (sb_len > 2)
                        sshdr->sense_key = (sense_buffer[2] & 0xf);
                if (sb_len > 7) {
                        sb_len = (sb_len < (sense_buffer[7] + 8)) ?
                                         sb_len : (sense_buffer[7] + 8);
                        if (sb_len > 12)
                                sshdr->asc = sense_buffer[12];
                        if (sb_len > 13)
                                sshdr->ascq = sense_buffer[13];
                }
        }

        return 1;
}


int scsi_execute_req(struct Scsi_Host *shost, struct scsi_device *sdev, const unsigned char *cmd,
		     int data_direction, void *buffer, unsigned bufflen,
		     struct scsi_sense_hdr *sshdr, int timeout, int retries, uint64_t block)
{
	//if(block != 1000000)
	//	printf("csi_execute_req: lock = %ld \n", block);        

	//printf("scsi_execute_req,	data_direction is %d\n", data_direction);
	//int kkk=0;
        //printf("scsi_execute_req got cmd is :");
        //for(kkk=0;kkk<16;kkk++)
        //        printf("%X ", cmd[kkk]);
        //printf("\n");
	char *sense = NULL;
	int result;
	
	if (sshdr) {
		sense = malloc(SCSI_SENSE_BUFFERSIZE);
		if (!sense)
			return DRIVER_ERROR << 24;
	}
	result = scsi_execute(shost, sdev, cmd, data_direction, buffer, bufflen,
			      sense, timeout, retries, 0, block);
	if (sshdr)
		scsi_normalize_sense(sense, SCSI_SENSE_BUFFERSIZE, sshdr);

	free(sense);
	return result;
}



/*
 * Function:    scsi_init_cmd_errh()
 *
 * Purpose:     Initialize cmd fields related to error handling.
 *
 * Arguments:   cmd     - command that is ready to be queued.
 *
 * Notes:       This function has the job of initializing a number of
 *              fields related to error handling.   Typically this will
 *              be called once for each command, as required.
 */
static void scsi_init_cmd_errh(struct scsi_cmnd *cmd)
{
        cmd->serial_number = 0;
        //memset(cmd->sense_buffer, 0, sizeof cmd->sense_buffer);
        memset(cmd->sense_buffer, 0, SCSI_SENSE_BUFFERSIZE);
	//printf("before COMMAND_SIZE len is %d\n", cmd->cmd_len);
        if (cmd->cmd_len == 0)
                cmd->cmd_len = COMMAND_SIZE(cmd->cmnd[0]);
	//printf("[scsi_init_cmd_errh]cmd->cmnd[0] >> 5 is %X, >> 5 & 7 is %X, cmd->cmd_len is %X\n", cmd->cmnd[0] >> 5, (cmd->cmnd[0] >> 5) & 7, cmd->cmd_len);
	//int i = 0;
	//for(i=0;i<8;i++)
	//	printf("scsi_command_size[%d] is %d\n", i, scsi_command_size[i]);
}


static void scsi_blk_pc_done(struct scsi_cmnd *cmd)
{
	//TODO
}

static int scsi_setup_blk_pc_cmnd(struct scsi_cmnd *cmd, int direction)
{
	if (!cmd)
	{
		printf("Cmd point is NULL, please prepare the cmd buffer!\n");
		return -1;
	}

	/*if (direction == NONE)
		cmd->sc_data_direction = DMA_NONE;
	else if (direction == WRITE)
		cmd->sc_data_direction = DMA_TO_DEVICE;
	else
		cmd->sc_data_direction = DMA_FROM_DEVICE;*/
	
	cmd->done = scsi_blk_pc_done;
	return 0;
}

/*
 * Setup a REQ_TYPE_FS command.  These are simple read/write request
 * from filesystems that still need to be translated to SCSI CDBs from
 * the ULD.
 */
static int scsi_setup_fs_cmnd(struct scsi_cmnd *cmd, const unsigned char *cmd_string, uint64_t block)
{
	if (!cmd)
	{
		printf("Cmd point is NULL, please prepare the cmd buffer!\n");
		return -1;
	}

	/*
	 * Initialize the actual SCSI command for this request.
	 */
	//TODO mend this function
	sd_init_command(cmd, cmd_string, block);

	return 0;
}

#if 0
static int scsi_prep_fn(struct request_queue *q, struct request *req)
{
	struct scsi_device *sdev = q->queuedata;
	int ret = BLKPREP_OK;

	/*
	 * If the device is not in running state we will reject some
	 * or all commands.
	 */
	if (unlikely(sdev->sdev_state != SDEV_RUNNING)) {
		switch (sdev->sdev_state) {
		case SDEV_OFFLINE:
			/*
			 * If the device is offline we refuse to process any
			 * commands.  The device must be brought online
			 * before trying any recovery commands.
			 */
			sdev_printk(KERN_ERR, sdev,
				    "rejecting I/O to offline device\n");
			ret = BLKPREP_KILL;
			break;
		case SDEV_DEL:
			/*
			 * If the device is fully deleted, we refuse to
			 * process any commands as well.
			 */
			sdev_printk(KERN_ERR, sdev,
				    "rejecting I/O to dead device\n");
			ret = BLKPREP_KILL;
			break;
		case SDEV_QUIESCE:
		case SDEV_BLOCK:
			/*
			 * If the devices is blocked we defer normal commands.
			 */
			if (!(req->cmd_flags & REQ_PREEMPT))
				ret = BLKPREP_DEFER;
			break;
		default:
			/*
			 * For any other not fully online state we only allow
			 * special commands.  In particular any user initiated
			 * command is not allowed.
			 */
			if (!(req->cmd_flags & REQ_PREEMPT))
				ret = BLKPREP_KILL;
			break;
		}

		if (ret != BLKPREP_OK)
			goto out;
	}

	switch (req->cmd_type) {
	case REQ_TYPE_BLOCK_PC:
		ret = scsi_setup_blk_pc_cmnd(sdev, req);
		break;
	case REQ_TYPE_FS:
		ret = scsi_setup_fs_cmnd(sdev, req);
		break;
	default:
		/*
		 * All other command types are not supported.
		 *
		 * Note that these days the SCSI subsystem does not use
		 * REQ_TYPE_SPECIAL requests anymore.  These are only used
		 * (directly or via blk_insert_request) by non-SCSI drivers.
		 */
		blk_dump_rq_flags(req, "SCSI bad req");
		ret = BLKPREP_KILL;
		break;
	}

 out:
	switch (ret) {
	case BLKPREP_KILL:
		req->errors = DID_NO_CONNECT << 16;
		break;
	case BLKPREP_DEFER:
		/*
		 * If we defer, the elv_next_request() returns NULL, but the
		 * queue must be restarted, so we plug here if no returning
		 * command will automatically do that.
		 */
		if (sdev->device_busy == 0)
			blk_plug_device(q);
		break;
	default:
		req->cmd_flags |= REQ_DONTPREP;
	}

	return ret;
}

/*
 * scsi_dev_queue_ready: if we can send requests to sdev, return 1 else
 * return 0.
 *
 * Called with the queue_lock held.
 */
static inline int scsi_dev_queue_ready(struct request_queue *q,
				  struct scsi_device *sdev)
{
	if (sdev->device_busy >= sdev->queue_depth)
		return 0;
	if (sdev->device_busy == 0 && sdev->device_blocked) {
		/*
		 * unblock after device_blocked iterates to zero
		 */
		if (--sdev->device_blocked == 0) {
			SCSI_LOG_MLQUEUE(3,
				   sdev_printk(KERN_INFO, sdev,
				   "unblocking device at zero depth\n"));
		} else {
			blk_plug_device(q);
			return 0;
		}
	}
	if (sdev->device_blocked)
		return 0;

	return 1;
}

/*
 * scsi_host_queue_ready: if we can send requests to shost, return 1 else
 * return 0. We must end up running the queue again whenever 0 is
 * returned, else IO can hang.
 *
 * Called with host_lock held.
 */
static inline int scsi_host_queue_ready(struct request_queue *q,
				   struct Scsi_Host *shost,
				   struct scsi_device *sdev)
{
	if (scsi_host_in_recovery(shost))
		return 0;
	if (shost->host_busy == 0 && shost->host_blocked) {
		/*
		 * unblock after host_blocked iterates to zero
		 */
		if (--shost->host_blocked == 0) {
			SCSI_LOG_MLQUEUE(3,
				printk("scsi%d unblocking host at zero depth\n",
					shost->host_no));
		} else {
			blk_plug_device(q);
			return 0;
		}
	}
	if ((shost->can_queue > 0 && shost->host_busy >= shost->can_queue) ||
	    shost->host_blocked || shost->host_self_blocked) {
		if (list_empty(&sdev->starved_entry))
			list_add_tail(&sdev->starved_entry, &shost->starved_list);
		return 0;
	}

	/* We're OK to process the command, so we can't be starved */
	if (!list_empty(&sdev->starved_entry))
		list_del_init(&sdev->starved_entry);

	return 1;
}

/*
 * Kill a request for a dead device
 */
static void scsi_kill_request(struct request *req, request_queue_t *q)
{
	struct scsi_cmnd *cmd = req->special;
	struct scsi_device *sdev = cmd->device;
	struct Scsi_Host *shost = sdev->host;

	blkdev_dequeue_request(req);

	if (unlikely(cmd == NULL)) {
		printk(KERN_CRIT "impossible request in %s.\n",
				 __FUNCTION__);
		BUG();
	}

	scsi_init_cmd_errh(cmd);
	cmd->result = DID_NO_CONNECT << 16;
	atomic_inc(&cmd->device->iorequest_cnt);

	/*
	 * SCSI request completion path will do scsi_device_unbusy(),
	 * bump busy counts.  To bump the counters, we need to dance
	 * with the locks as normal issue path does.
	 */
	sdev->device_busy++;
	spin_unlock(sdev->request_queue->queue_lock);
	spin_lock(shost->host_lock);
	shost->host_busy++;
	spin_unlock(shost->host_lock);
	spin_lock(sdev->request_queue->queue_lock);

	__scsi_done(cmd);
}

static void scsi_softirq_done(struct request *rq)
{
	struct scsi_cmnd *cmd = rq->completion_data;
	unsigned long wait_for = (cmd->allowed + 1) * cmd->timeout_per_command;
	int disposition;

	INIT_LIST_HEAD(&cmd->eh_entry);

	disposition = scsi_decide_disposition(cmd);
	if (disposition != SUCCESS &&
	    time_before(cmd->jiffies_at_alloc + wait_for, jiffies)) {
		sdev_printk(KERN_ERR, cmd->device,
			    "timing out command, waited %lus\n",
			    wait_for/HZ);
		disposition = SUCCESS;
	}
			
	scsi_log_completion(cmd, disposition);

	switch (disposition) {
		case SUCCESS:
			scsi_finish_command(cmd);
			break;
		case NEEDS_RETRY:
			scsi_queue_insert(cmd, SCSI_MLQUEUE_EH_RETRY);
			break;
		case ADD_TO_MLQUEUE:
			scsi_queue_insert(cmd, SCSI_MLQUEUE_DEVICE_BUSY);
			break;
		default:
			if (!scsi_eh_scmd_add(cmd, 0))
				scsi_finish_command(cmd);
	}
}
#endif


/*
 * Function:    scsi_request_fn()
 *
 * Purpose:     Main strategy routine for SCSI.
 *
 * Arguments:   q       - Pointer to actual queue.
 *
 * Returns:     Nothing
 *
 * Lock status: IO request lock assumed to be held when called.
 */
static void scsi_request_fn(struct Scsi_Host *shost, struct scsi_device *sdev, const unsigned char *cmd_string, enum dma_data_direction data_direction, void *buffer, unsigned bufflen, uint64_t block)
{
	//printf("scsi_request_fn, bufflen is %d\n", bufflen);
	struct scsi_cmnd *cmd;

	/*
	 * get next queueable request.  We do this early to make sure
	 * that the request is fully prepared even if we cannot 
	 * accept it.
	 */

	//TODO release cmd buffer
	cmd = malloc(sizeof(struct scsi_cmnd));
	memset(cmd, 0, sizeof(struct scsi_cmnd));
	if(cmd == NULL)
		printf("----------------------------------\n");
	cmd->device = sdev;
	cmd->request_buffer = buffer;
	cmd->request_bufflen = bufflen;
	cmd->sc_data_direction = data_direction;
	//printf("cmd->sc_data_direction is %d\n", cmd->sc_data_direction);
	memset(cmd->cmnd, 0, MAX_COMMAND_SIZE);
	//cmd->cmd_len = (uint8_t)COMMAND_SIZE(cmd->cmnd[0]);
	int cmd_type = REQ_TYPE_BLOCK_PC;
	if(strcmp(cmd_string, "read") == 0)
		cmd_type = REQ_TYPE_FS;
	if(strcmp(cmd_string, "write") == 0)
                cmd_type = REQ_TYPE_FS;
	

	switch (cmd_type) {
		//login is BLOCK_PC
		case REQ_TYPE_BLOCK_PC:
			memcpy(cmd->cmnd, cmd_string, MAX_COMMAND_SIZE);
			scsi_setup_blk_pc_cmnd(cmd, DMA_FROM_DEVICE);
			cmd->cmd_len = (uint8_t)COMMAND_SIZE(cmd->cmnd[0]);
			break;
		case REQ_TYPE_FS:
			//TODO read and write must use this function
			scsi_setup_fs_cmnd(cmd, cmd_string, block);
			scsi_init_cmd_errh(cmd);
			break;
		default:
			/*
			 * All other command types are not supported.
			 *
			 * Note that these days the SCSI subsystem does not use
			 * REQ_TYPE_SPECIAL requests anymore.  These are only used
			 * (directly or via blk_insert_request) by non-SCSI drivers.
			 */
			printf("Not support type!\n");
			break;
	}

	//printf("cmd->cmd_len is %d\n", cmd->cmd_len);
	//printf("cmd->device->lun is %d\n", cmd->device->lun);
	if(cmd->request_buffer == NULL)
		printf("cmd->request_buffer is NULL\n");
	else
		 ;//printf("cmd->request_buffer is not NULL\n");


	/*
	 * Dispatch the command to the low-level driver.
	 */
	scsi_dispatch_cmd(shost, sdev, cmd);
	free(cmd);
	//printf("exit scsi_request_fn\n");
}



//static void scsi_request_fn(struct Scsi_Host *shost, struct scsi_device *sdev, const unsigned char *cmd_string, enum dma_data_direction data_direction, void *buffer, unsigned bufflen, uint64_t block)
void scsi_request_fn_work(struct Scsi_Host *shost, struct scsi_device *sdev, cvmx_wqe_t * work)
{
	//Renjs
	//numwin ++;
	//printf("scsi_request_fn_work\n");
	iSCSI_Params * params_ptr = (iSCSI_Params *) work->packet_data;

	struct scsi_cmnd *cmd = (struct scsi_cmnd *)cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	memset(cmd, 0, CVMX_FPA_PACKET_POOL_SIZE);
	cmd->device = sdev;
	cmd->request_buffer = params_ptr->data_head;//TODO
	cmd->request_buffer_ptr = params_ptr->data_head;
	cmd->request_bufflen = params_ptr->cmd.byte_size;
	//printf("scsi_request_fn_work1:   cmd->request_bufflen =  %d\n",cmd->request_bufflen );
	//printf("sc cmd address is %p,	request_buffer is %llX,		request_bufflen is %d\n", cmd, cmd->request_buffer, cmd->request_bufflen);
	if(params_ptr->cmd.cmd_type == iscsi_Read_asyn)
		cmd->sc_data_direction = DMA_FROM_DEVICE;
	else
		cmd->sc_data_direction = DMA_TO_DEVICE;
	//memset(cmd->cmnd, 0, MAX_COMMAND_SIZE);
	
	if(params_ptr->cmd.cmd_type == iscsi_Read_asyn)
		scsi_setup_fs_cmnd(cmd, "read", params_ptr->cmd.start_sector);
	else
		scsi_setup_fs_cmnd(cmd, "write", params_ptr->cmd.start_sector);
	//printf("=================%X\n", cmd->cmnd[0]);
	scsi_init_cmd_errh(cmd);
	
	cmd->app_work = (uint64_t) work;

	//TODO set request_buffer
	//if(cmd->request_buffer == NULL)
	//	printf("cmd->request_buffer is NULL\n");

	/*
	 * Dispatch the command to the low-level driver.
	 */
	//printf("scsi_request_fn_work2:   cmd->request_bufflen =  %d\n",cmd->request_bufflen );
	scsi_dispatch_cmd(shost, sdev, cmd);

	//cvm_common_free_fpa_buffer(cmd, CVMX_FPA_PACKET_POOL, 0);
}






/**
 *	scsi_mode_sense - issue a mode sense, falling back from 10 to 
 *		six bytes if necessary.
 *	@sdev:	SCSI device to be queried
 *	@dbd:	set if mode sense will allow block descriptors to be returned
 *	@modepage: mode page being requested
 *	@buffer: request buffer (may not be smaller than eight bytes)
 *	@len:	length of request buffer.
 *	@timeout: command timeout
 *	@retries: number of retries before failing
 *	@data: returns a structure abstracting the mode header data
 *	@sense: place to put sense data (or NULL if no sense to be collected).
 *		must be SCSI_SENSE_BUFFERSIZE big.
 *
 *	Returns zero if unsuccessful, or the header offset (either 4
 *	or 8 depending on whether a six or ten byte command was
 *	issued) if successful.
 **/
int
scsi_mode_sense(struct scsi_device *sdev, int dbd, int modepage,
		  unsigned char *buffer, int len, int timeout, int retries,
		  struct scsi_mode_data *data, struct scsi_sense_hdr *sshdr)
{
	unsigned char cmd[12];
	int use_10_for_ms;
	int header_length;
	int result;
	struct scsi_sense_hdr my_sshdr;

	memset(data, 0, sizeof(*data));
	memset(&cmd[0], 0, 12);
	cmd[1] = dbd & 0x18;	/* allows DBD and LLBA bits */
	cmd[2] = modepage;

	/* caller might not be interested in sense, but we need it */
	if (!sshdr)
		sshdr = &my_sshdr;

 retry:
	use_10_for_ms = sdev->use_10_for_ms;

	if (use_10_for_ms) {
		if (len < 8)
			len = 8;

		cmd[0] = MODE_SENSE_10;
		cmd[8] = len;
		header_length = 8;
	} else {
		if (len < 4)
			len = 4;

		cmd[0] = MODE_SENSE;
		cmd[4] = len;
		header_length = 4;
	}

	memset(buffer, 0, len);
	printf("use_10_for_ms is %d\n", use_10_for_ms);
	printf("len is %d\n", len);

	result = scsi_execute_req(sdev->host, sdev, cmd, DMA_FROM_DEVICE, buffer, len,
				  sshdr, timeout, retries, 0);

	/* This code looks awful: what it's doing is making sure an
	 * ILLEGAL REQUEST sense return identifies the actual command
	 * byte as the problem.  MODE_SENSE commands can return
	 * ILLEGAL REQUEST if the code page isn't supported */

	if (use_10_for_ms && !scsi_status_is_good(result) &&
	    (driver_byte(result) & DRIVER_SENSE)) {
		if (scsi_sense_valid(sshdr)) {
			if ((sshdr->sense_key == ILLEGAL_REQUEST) &&
			    (sshdr->asc == 0x20) && (sshdr->ascq == 0)) {
				/* 
				 * Invalid command operation code
				 */
				sdev->use_10_for_ms = 0;
				goto retry;
			}
		}
	}

	if(scsi_status_is_good(result)) {
		if (buffer[0] == 0x86 && buffer[1] == 0x0b &&
			     (modepage == 6 || modepage == 8)) {
			printf("AAAAAAAAAAAAAAAA\n");
			/* Initio breakage? */
			header_length = 0;
			data->length = 13;
			data->medium_type = 0;
			data->device_specific = 0;
			data->longlba = 0;
			data->block_descriptor_length = 0;
		} else if(use_10_for_ms) {
			printf("BBBBBBBBBBBBBBB\n");
			data->length = buffer[0]*256 + buffer[1] + 2;
			data->medium_type = buffer[2];
			data->device_specific = buffer[3];
			data->longlba = buffer[4] & 0x01;
			data->block_descriptor_length = buffer[6]*256
				+ buffer[7];
		} else {
			printf("CCCCCCCCCCCCCCCCC\n");
			data->length = buffer[0] + 1;
			data->medium_type = buffer[1];
			data->device_specific = buffer[2];
			data->block_descriptor_length = buffer[3];
		}
		data->header_length = header_length;
		printf("data->header_length:%d\n", data->header_length);
                printf("data->length:%d\n", data->length);
                printf("data->block_descriptor_length:%d\n", data->block_descriptor_length);
	}

	return result;
}

/**
 *	scsi_device_set_state - Take the given device through the device
 *		state model.
 *	@sdev:	scsi device to change the state of.
 *	@state:	state to change to.
 *
 *	Returns zero if unsuccessful or an error if the requested 
 *	transition is illegal.
 **/
int
scsi_device_set_state(struct scsi_device *sdev, enum scsi_device_state state)
{
	enum scsi_device_state oldstate = sdev->sdev_state;

	if (state == oldstate)
		return 0;

	switch (state) {
	case SDEV_CREATED:
		/* There are no legal states that come back to
		 * created.  This is the manually initialised start
		 * state */
		goto illegal;
			
	case SDEV_RUNNING:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_OFFLINE:
		case SDEV_QUIESCE:
		case SDEV_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_QUIESCE:
		switch (oldstate) {
		case SDEV_RUNNING:
		case SDEV_OFFLINE:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_OFFLINE:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_RUNNING:
		case SDEV_QUIESCE:
		case SDEV_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_BLOCK:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_RUNNING:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_CANCEL:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_RUNNING:
		case SDEV_QUIESCE:
		case SDEV_OFFLINE:
		case SDEV_BLOCK:
			break;
		default:
			goto illegal;
		}
		break;

	case SDEV_DEL:
		switch (oldstate) {
		case SDEV_CREATED:
		case SDEV_RUNNING:
		case SDEV_OFFLINE:
		case SDEV_CANCEL:
			break;
		default:
			goto illegal;
		}
		break;

	}
	sdev->sdev_state = state;
	return 0;

 illegal:
	printf("Illegal state transition\n");
	return -1;
}

