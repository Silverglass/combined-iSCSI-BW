/*
 *  hosts.c Copyright (C) 1992 Drew Eckhardt
 *          Copyright (C) 1993, 1994, 1995 Eric Youngdale
 *          Copyright (C) 2002-2003 Christoph Hellwig
 *
 *  mid to lowlevel SCSI driver interface
 *      Initial versions: Drew Eckhardt
 *      Subsequent revisions: Eric Youngdale
 *
 *  <drew@colorado.edu>
 *
 *  Jiffies wrap fixes (host->resetting), 3 Dec 1998 Andrea Arcangeli
 *  Added QLOGIC QLA1280 SCSI controller kernel host support. 
 *     August 4, 1999 Fred Lewis, Intel DuPont
 *
 *  Updated to reflect the new initialization scheme for the higher 
 *  level of scsi drivers (sd/sr/st)
 *  September 17, 2000 Torben Mathiasen <tmm@image.dk>
 *
 *  Restructured scsi_host lists and associated functions.
 *  September 04, 2002 Mike Anderson (andmike@us.ibm.com)
 */

#include "device.h"
#include "scsi_lib.h"
#include "hosts.h"

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

#define MAX_SCSI_HOST_NUM	100
CVMX_SHARED int Scsi_Host_Num;
CVMX_SHARED uint64_t Scsi_Host_List[MAX_SCSI_HOST_NUM];
struct list_head Scsi_Host_List_head;



static int scsi_host_next_hn;		/* host_no for next new host */


static const struct {
	enum scsi_host_state	value;
	char			*name;
} shost_states[] = {
	{ SHOST_CREATED, "created" },
	{ SHOST_RUNNING, "running" },
	{ SHOST_CANCEL, "cancel" },
	{ SHOST_DEL, "deleted" },
	{ SHOST_RECOVERY, "recovery" },
	{ SHOST_CANCEL_RECOVERY, "cancel/recovery" },
	{ SHOST_DEL_RECOVERY, "deleted/recovery", },
};
const char *scsi_host_state_name(enum scsi_host_state state)
{
	int i;
	char *name = NULL;

	for (i = 0; i < ARRAY_SIZE(shost_states); i++) {
		if (shost_states[i].value == state) {
			name = shost_states[i].name;
			break;
		}
	}
	return name;
}


/**
 *	scsi_host_set_state - Take the given host through the host
 *		state model.
 *	@shost:	scsi host to change the state of.
 *	@state:	state to change to.
 *
 *	Returns zero if unsuccessful or an error if the requested
 *	transition is illegal.
 **/
int scsi_host_set_state(struct Scsi_Host *shost, enum scsi_host_state state)
{
	enum scsi_host_state oldstate = shost->shost_state;

	if (state == oldstate)
		return 0;

	switch (state) {
	case SHOST_CREATED:
		/* There are no legal states that come back to
		 * created.  This is the manually initialised start
		 * state */
		goto illegal;

	case SHOST_RUNNING:
		switch (oldstate) {
		case SHOST_CREATED:
		case SHOST_RECOVERY:
			break;
		default:
			goto illegal;
		}
		break;

	case SHOST_RECOVERY:
		switch (oldstate) {
		case SHOST_RUNNING:
			break;
		default:
			goto illegal;
		}
		break;

	case SHOST_CANCEL:
		switch (oldstate) {
		case SHOST_CREATED:
		case SHOST_RUNNING:
		case SHOST_CANCEL_RECOVERY:
			break;
		default:
			goto illegal;
		}
		break;

	case SHOST_DEL:
		switch (oldstate) {
		case SHOST_CANCEL:
		case SHOST_DEL_RECOVERY:
			break;
		default:
			goto illegal;
		}
		break;

	case SHOST_CANCEL_RECOVERY:
		switch (oldstate) {
		case SHOST_CANCEL:
		case SHOST_RECOVERY:
			break;
		default:
			goto illegal;
		}
		break;

	case SHOST_DEL_RECOVERY:
		switch (oldstate) {
		case SHOST_CANCEL_RECOVERY:
			break;
		default:
			goto illegal;
		}
		break;
	}
	shost->shost_state = state;
	return 0;

 illegal:
	printf("Illegal host state transition%s->%s\n", scsi_host_state_name(oldstate), scsi_host_state_name(state));
	return -1;
}

/**
 * scsi_add_host - add a scsi host
 * @shost:	scsi host pointer to add
 * @dev:	a struct device of type scsi class
 *
 * Return value: 
 * 	0 on success / != 0 for error
 **/
int scsi_add_host(struct Scsi_Host *shost)
{
	printf("scsi_add_host shost address is %X\n", shost);
	Scsi_Host_List[Scsi_Host_Num++] = (uint64_t) shost;

	struct scsi_host_template *sht = shost->hostt;

	printf("scsi%d : %s\n", shost->host_no, sht->info ? sht->info(shost) : sht->name);

	scsi_host_set_state(shost, SHOST_RUNNING);

	return 0;
}


/**
 * scsi_host_alloc - register a scsi host adapter instance.
 * @sht:	pointer to scsi host template
 * @privsize:	extra bytes to allocate for driver
 *
 * Note:
 * 	Allocate a new Scsi_Host and perform basic initialization.
 * 	The host is not published to the scsi midlayer until scsi_add_host
 * 	is called.
 *
 * Return value:
 * 	Pointer to a new Scsi_Host
 **/
struct Scsi_Host *scsi_host_alloc(struct scsi_host_template *sht, int privsize)
{
	struct Scsi_Host *shost;
	//int rval;

	//shost = malloc(sizeof(struct Scsi_Host) + privsize);
	shost = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	printf("000000000000000000000	shost is %p,	shost->hostdata is %p\n", shost, shost->hostdata);
	if(CVMX_FPA_PACKET_POOL_SIZE < sizeof(struct Scsi_Host) + privsize)
		printf("CVMX_FPA_PACKET_POOL_SIZE is smaller than sizeof(struct Scsi_Host) + privsize\n");
	if (!shost)
		return NULL;

	//shost->host_lock = &shost->default_lock;
	//spin_lock_init(shost->host_lock);
	shost->shost_state = SHOST_CREATED;
	INIT_LIST_HEAD(&shost->__devices);
	INIT_LIST_HEAD(&shost->__targets);
	INIT_LIST_HEAD(&shost->eh_cmd_q);
	INIT_LIST_HEAD(&shost->starved_list);
	//init_waitqueue_head(&shost->host_wait);

	//mutex_init(&shost->scan_mutex);

	shost->host_no = scsi_host_next_hn++; /* XXX(hch): still racy */
	shost->dma_channel = 0xff;

	/* These three are default values which can be overridden */
	shost->max_channel = 0;
	shost->max_id = 8;
	shost->max_lun = 8;

	/* Give each shost a default transportt */
	//shost->transportt = &blank_transport_template;

	/*
	 * All drivers right now should be able to handle 12 byte
	 * commands.  Every so often there are requests for 16 byte
	 * commands, but individual low-level drivers need to certify that
	 * they actually do something sensible with such commands.
	 */
	shost->max_cmd_len = 12;
	shost->hostt = sht;
	shost->this_id = sht->this_id;
	shost->can_queue = sht->can_queue;
	shost->sg_tablesize = sht->sg_tablesize;
	shost->cmd_per_lun = sht->cmd_per_lun;
	shost->unchecked_isa_dma = sht->unchecked_isa_dma;
	shost->use_clustering = sht->use_clustering;
	shost->ordered_tag = sht->ordered_tag;

	if (sht->max_host_blocked)
		shost->max_host_blocked = sht->max_host_blocked;
	else
		shost->max_host_blocked = SCSI_DEFAULT_HOST_BLOCKED;

	/*
	 * If the driver imposes no hard sector transfer limit, start at
	 * machine infinity initially.
	 */
	if (sht->max_sectors)
		shost->max_sectors = sht->max_sectors;
	else
		shost->max_sectors = SCSI_DEFAULT_MAX_SECTORS;

	/*
	 * assume a 4GB boundary, if not set
	 */
	if (sht->dma_boundary)
		shost->dma_boundary = sht->dma_boundary;
	else
		shost->dma_boundary = 0xffffffff;

	//rval = scsi_setup_command_freelist(shost);
	//if (rval)
	//	goto fail_kfree;

	//device_initialize(&shost->shost_gendev);
	//snprintf(shost->shost_gendev.bus_id, BUS_ID_SIZE, "host%d",
	//	shost->host_no);
	//shost->shost_gendev.release = scsi_host_dev_release;

	//class_device_initialize(&shost->shost_classdev);
	//shost->shost_classdev.dev = &shost->shost_gendev;
	//shost->shost_classdev.class = &shost_class;
	//snprintf(shost->shost_classdev.class_id, BUS_ID_SIZE, "host%d",
	//	  shost->host_no);

	//shost->ehandler = kthread_run(scsi_error_handler, shost,
	//		"scsi_eh_%d", shost->host_no);
	//if (IS_ERR(shost->ehandler)) {
	//	rval = PTR_ERR(shost->ehandler);
	//	goto fail_destroy_freelist;
	//}

	//scsi_proc_hostdir_add(shost->hostt);
	return shost;
}


//int64_t scsi_read(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group)
int64_t scsi_read(cvmx_wqe_t * work)
{
	iSCSI_Params * params_ptr = (iSCSI_Params *) work->packet_data;
	if(Scsi_Host_List[params_ptr->cmd.lun] == 0)
	{
		printf("[Host]scsi device %d does not exist!\n", params_ptr->cmd.lun);
		return -1;
	}

	struct Scsi_Host *shost = (struct Scsi_Host *)	Scsi_Host_List[params_ptr->cmd.lun];

	struct scsi_device * sdev;

	if(&(shost->__devices) == NULL)
		printf("shost->__devices is NULL\n");
	list_for_each_entry(sdev, &shost->__devices, siblings) {		
		if(sdev != NULL)
    //if(sdev->lun == params_ptr->cmd.lun)
		{
			//printf("found sdev->lun!\n");
			break;
		}
	}	
	if(sdev == NULL)
		printf("can not found device!\n");	

	//printf("sdev adderss is %p\n", sdev);

	scsi_request_fn_work(shost, sdev, work);
		

	/*scsi_execute_req(shost, sdev, "read",
                     DMA_FROM_DEVICE, buffer, bufflen,
                     &sshdr, 0, 3, block);*/
	
	return 0;	
}

int numwin ;

int64_t scsi_write(cvmx_wqe_t * work)
{
	//Renjs
	//numwin ++ ;
	iSCSI_Params * params_ptr = (iSCSI_Params *) work->packet_data;
	if(Scsi_Host_List[params_ptr->cmd.lun] == 0)
	{
		printf("[Host]scsi device %d does not exist!\n", params_ptr->cmd.lun);
		return -1;
	}

	struct Scsi_Host *shost = (struct Scsi_Host *)  Scsi_Host_List[params_ptr->cmd.lun];

	struct scsi_device * sdev;

	if(&(shost->__devices) == NULL)
		printf("shost->__devices is NULL\n");
	list_for_each_entry(sdev, &shost->__devices, siblings) {
		if(sdev != NULL)
    //if(sdev->lun == params_ptr->cmd.lun)
		{
			//printf("found sdev->lun!\n");
			break;
		}
	}
	if(sdev == NULL)
		printf("can not found device!\n");

	//printf("sdev adderss is %p\n", sdev);

	scsi_request_fn_work(shost, sdev, work);
	return 0;
}

#if 0
int64_t scsi_write(uint64_t lun, uint64_t start_sector, uint64_t byte_size, data_list_t * data_head, uint64_t context, uint64_t group)
{
        struct Scsi_Host_List * ptr;
        list_for_each_entry(ptr, &Scsi_Host_List_head, list)
        {
                if(ptr != NULL)
                    break;
        }

	struct scsi_device * sdev;

        list_for_each_entry(sdev, &ptr->shost->__devices, siblings) {
		if(sdev->lun == dev)
			break;
        }
        if(sdev == NULL)
                printf("can not found device!\n");

        struct scsi_sense_hdr sshdr;

        scsi_execute_req(ptr->shost, sdev, "write",
                     DMA_TO_DEVICE, buffer, bufflen,
                     &sshdr, 0, 3, block);

        return 0;
}
#endif
