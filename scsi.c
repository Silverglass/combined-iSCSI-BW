/*
 *  scsi.c Copyright (C) 1992 Drew Eckhardt
 *         Copyright (C) 1993, 1994, 1995, 1999 Eric Youngdale
 *         Copyright (C) 2002, 2003 Christoph Hellwig
 *
 *  generic mid-level SCSI driver
 *      Initial versions: Drew Eckhardt
 *      Subsequent revisions: Eric Youngdale
 *
 *  <drew@colorado.edu>
 *
 *  Bug correction thanks go to :
 *      Rik Faith <faith@cs.unc.edu>
 *      Tommy Thorn <tthorn>
 *      Thomas Wuensche <tw@fgb1.fgb.mw.tu-muenchen.de>
 *
 *  Modified by Eric Youngdale eric@andante.org or ericy@gnu.ai.mit.edu to
 *  add scatter-gather, multiple outstanding request, and other
 *  enhancements.
 *
 *  Native multichannel, wide scsi, /proc/scsi and hot plugging
 *  support added by Michael Neuffer <mike@i-connect.net>
 *
 *  Added request_module("scsi_hostadapter") for kerneld:
 *  (Put an "alias scsi_hostadapter your_hostadapter" in /etc/modprobe.conf)
 *  Bjorn Ekwall  <bj0rn@blox.se>
 *  (changed to kmod)
 *
 *  Major improvements to the timeout, abort, and reset processing,
 *  as well as performance modifications for large queue depths by
 *  Leonard N. Zubkoff <lnz@dandelion.com>
 *
 *  Converted cli() code to spinlocks, Ingo Molnar
 *
 *  Jiffies wrap fixes (host->resetting), 3 Dec 1998 Andrea Arcangeli
 *
 *  out_of_space hacks, D. Gilbert (dpg) 990608
 */

#include "device.h"
#include "scsi.h"

static void scsi_done(struct scsi_cmnd *cmd){}

/*
 * Definitions and constants.
 */

#define MIN_RESET_DELAY (2*HZ)

/* Do not call reset on error if we just did a reset within 15 sec. */
#define MIN_RESET_PERIOD (15*HZ)

/*
 * Macro to determine the size of SCSI command. This macro takes vendor
 * unique commands into account. SCSI commands in groups 6 and 7 are
 * vendor unique and we will depend upon the command length being
 * supplied correctly in cmd_len.
 */
#define CDB_SIZE(cmd)	(((((cmd)->cmnd[0] >> 5) & 7) < 6) ? \
				COMMAND_SIZE((cmd)->cmnd[0]) : (cmd)->cmd_len)

/*
 * Note - the initial logging level can be set here to log events at boot time.
 * After the system is up, you may enable logging via the /proc interface.
 */
unsigned int scsi_logging_level;

/* NB: These are exposed through /proc/scsi/scsi and form part of the ABI.
 * You may not alter any existing entry (although adding new ones is
 * encouraged once assigned by ANSI/INCITS T10
 */
static const char *const scsi_device_types[] = {
	"Direct-Access    ",
	"Sequential-Access",
	"Printer          ",
	"Processor        ",
	"WORM             ",
	"CD-ROM           ",
	"Scanner          ",
	"Optical Device   ",
	"Medium Changer   ",
	"Communications   ",
	"ASC IT8          ",
	"ASC IT8          ",
	"RAID             ",
	"Enclosure        ",
	"Direct-Access-RBC",
	"Optical card     ",
	"Bridge controller",
	"Object storage   ",
	"Automation/Drive ",
};

const char * scsi_device_type(unsigned type)
{
	if (type == 0x1e)
		return "Well-known LUN   ";
	if (type == 0x1f)
		return "No Device        ";
	if (type >= ARRAY_SIZE(scsi_device_types))
		return "Unknown          ";
	return scsi_device_types[type];
}


/**
 * __scsi_device_lookup_by_target - find a device given the target (UNLOCKED)
 * @starget:    SCSI target pointer
 * @lun:        SCSI Logical Unit Number
 *
 * Looks up the scsi_device with the specified @lun for a give
 * @starget. The returned scsi_device does not have an additional
 * reference.  You must hold the host's host_lock over this call and
 * any access to the returned scsi_device.
 *
 * Note:  The only reason why drivers would want to use this is because
 * they're need to access the device list in irq context.  Otherwise you
 * really want to use scsi_device_lookup_by_target instead.
 **/
struct scsi_device *__scsi_device_lookup_by_target(struct scsi_target *starget,
                                                   uint32_t lun)
{
        struct scsi_device *sdev;

        list_for_each_entry(sdev, &starget->devices, same_target_siblings) {
                if (sdev->lun ==lun)
                        return sdev;
        }

        return NULL;
}



/**
 * scsi_device_lookup_by_target - find a device given the target
 * @starget:    SCSI target pointer
 * @lun:        SCSI Logical Unit Number
 *
 * Looks up the scsi_device with the specified @channel, @id, @lun for a
 * give host.  The returned scsi_device has an additional reference that
 * needs to be release with scsi_host_put once you're done with it.
 **/
struct scsi_device *scsi_device_lookup_by_target(struct Scsi_Host *shost, struct scsi_target *starget,
                                                 uint32_t lun)
{
        struct scsi_device *sdev;

        sdev = __scsi_device_lookup_by_target(starget, lun);

        return sdev;
}


/*struct scsi_host_cmd_pool {
	struct kmem_cache	*slab;
	unsigned int	users;
	char		*name;
	unsigned int	slab_flags;
	gfp_t		gfp_mask;
};

static struct scsi_host_cmd_pool scsi_cmd_pool = {
	.name		= "scsi_cmd_cache",
	.slab_flags	= SLAB_HWCACHE_ALIGN,
};

static struct scsi_host_cmd_pool scsi_cmd_dma_pool = {
	.name		= "scsi_cmd_cache(DMA)",
	.slab_flags	= SLAB_HWCACHE_ALIGN|SLAB_CACHE_DMA,
	.gfp_mask	= __GFP_DMA,
};*/

//static DEFINE_MUTEX(host_cmd_pool_mutex);

#if 0
struct scsi_cmnd *__scsi_get_command(struct Scsi_Host *shost, gfp_t gfp_mask)
{
	struct scsi_cmnd *cmd;

	cmd = kmem_cache_alloc(shost->cmd_pool->slab,
			gfp_mask | shost->cmd_pool->gfp_mask);

	if (unlikely(!cmd)) {
		unsigned long flags;

		spin_lock_irqsave(&shost->free_list_lock, flags);
		if (likely(!list_empty(&shost->free_list))) {
			cmd = list_entry(shost->free_list.next,
					 struct scsi_cmnd, list);
			list_del_init(&cmd->list);
		}
		spin_unlock_irqrestore(&shost->free_list_lock, flags);
	}

	return cmd;
}
EXPORT_SYMBOL_GPL(__scsi_get_command);

/*
 * Function:	scsi_get_command()
 *
 * Purpose:	Allocate and setup a scsi command block
 *
 * Arguments:	dev	- parent scsi device
 *		gfp_mask- allocator flags
 *
 * Returns:	The allocated scsi command structure.
 */
struct scsi_cmnd *scsi_get_command(struct scsi_device *dev, gfp_t gfp_mask)
{
	struct scsi_cmnd *cmd;

	/* Bail if we can't get a reference to the device */
	if (!get_device(&dev->sdev_gendev))
		return NULL;

	cmd = __scsi_get_command(dev->host, gfp_mask);

	if (likely(cmd != NULL)) {
		unsigned long flags;

		memset(cmd, 0, sizeof(*cmd));
		cmd->device = dev;
		init_timer(&cmd->eh_timeout);
		INIT_LIST_HEAD(&cmd->list);
		spin_lock_irqsave(&dev->list_lock, flags);
		list_add_tail(&cmd->list, &dev->cmd_list);
		spin_unlock_irqrestore(&dev->list_lock, flags);
		cmd->jiffies_at_alloc = jiffies;
	} else
		put_device(&dev->sdev_gendev);

	return cmd;
}

void __scsi_put_command(struct Scsi_Host *shost, struct scsi_cmnd *cmd,
			struct device *dev)
{
	unsigned long flags;

	/* changing locks here, don't need to restore the irq state */
	spin_lock_irqsave(&shost->free_list_lock, flags);
	if (unlikely(list_empty(&shost->free_list))) {
		list_add(&cmd->list, &shost->free_list);
		cmd = NULL;
	}
	spin_unlock_irqrestore(&shost->free_list_lock, flags);

	if (likely(cmd != NULL))
		kmem_cache_free(shost->cmd_pool->slab, cmd);

	put_device(dev);
}

/*
 * Function:	scsi_put_command()
 *
 * Purpose:	Free a scsi command block
 *
 * Arguments:	cmd	- command block to free
 *
 * Returns:	Nothing.
 *
 * Notes:	The command must not belong to any lists.
 */
void scsi_put_command(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	unsigned long flags;

	/* serious error if the command hasn't come from a device list */
	spin_lock_irqsave(&cmd->device->list_lock, flags);
	BUG_ON(list_empty(&cmd->list));
	list_del_init(&cmd->list);
	spin_unlock_irqrestore(&cmd->device->list_lock, flags);

	__scsi_put_command(cmd->device->host, cmd, &sdev->sdev_gendev);
}

/*
 * Function:	scsi_setup_command_freelist()
 *
 * Purpose:	Setup the command freelist for a scsi host.
 *
 * Arguments:	shost	- host to allocate the freelist for.
 *
 * Returns:	Nothing.
 */
int scsi_setup_command_freelist(struct Scsi_Host *shost)
{
	struct scsi_host_cmd_pool *pool;
	struct scsi_cmnd *cmd;

	spin_lock_init(&shost->free_list_lock);
	INIT_LIST_HEAD(&shost->free_list);

	/*
	 * Select a command slab for this host and create it if not
	 * yet existant.
	 */
	mutex_lock(&host_cmd_pool_mutex);
	pool = (shost->unchecked_isa_dma ? &scsi_cmd_dma_pool : &scsi_cmd_pool);
	if (!pool->users) {
		pool->slab = kmem_cache_create(pool->name,
				sizeof(struct scsi_cmnd), 0,
				pool->slab_flags, NULL, NULL);
		if (!pool->slab)
			goto fail;
	}

	pool->users++;
	shost->cmd_pool = pool;
	mutex_unlock(&host_cmd_pool_mutex);

	/*
	 * Get one backup command for this host.
	 */
	cmd = kmem_cache_alloc(shost->cmd_pool->slab,
			GFP_KERNEL | shost->cmd_pool->gfp_mask);
	if (!cmd)
		goto fail2;
	list_add(&cmd->list, &shost->free_list);		
	return 0;

 fail2:
	if (!--pool->users)
		kmem_cache_destroy(pool->slab);
	return -ENOMEM;
 fail:
	mutex_unlock(&host_cmd_pool_mutex);
	return -ENOMEM;

}

/*
 * Function:	scsi_destroy_command_freelist()
 *
 * Purpose:	Release the command freelist for a scsi host.
 *
 * Arguments:	shost	- host that's freelist is going to be destroyed
 */
void scsi_destroy_command_freelist(struct Scsi_Host *shost)
{
	while (!list_empty(&shost->free_list)) {
		struct scsi_cmnd *cmd;

		cmd = list_entry(shost->free_list.next, struct scsi_cmnd, list);
		list_del_init(&cmd->list);
		kmem_cache_free(shost->cmd_pool->slab, cmd);
	}

	mutex_lock(&host_cmd_pool_mutex);
	if (!--shost->cmd_pool->users)
		kmem_cache_destroy(shost->cmd_pool->slab);
	mutex_unlock(&host_cmd_pool_mutex);
}
#endif

#ifdef CONFIG_SCSI_LOGGING
void scsi_log_send(struct scsi_cmnd *cmd)
{
	unsigned int level;
	struct scsi_device *sdev;

	/*
	 * If ML QUEUE log level is greater than or equal to:
	 *
	 * 1: nothing (match completion)
	 *
	 * 2: log opcode + command of all commands
	 *
	 * 3: same as 2 plus dump cmd address
	 *
	 * 4: same as 3 plus dump extra junk
	 */
	if (unlikely(scsi_logging_level)) {
		level = SCSI_LOG_LEVEL(SCSI_LOG_MLQUEUE_SHIFT,
				       SCSI_LOG_MLQUEUE_BITS);
		if (level > 1) {
			sdev = cmd->device;
			sdev_printk(KERN_INFO, sdev, "send ");
			if (level > 2)
				printk("0x%p ", cmd);
			/*
			 * spaces to match disposition and cmd->result
			 * output in scsi_log_completion.
			 */
			printk("                 ");
			scsi_print_command(cmd);
			if (level > 3) {
				printk(KERN_INFO "buffer = 0x%p, bufflen = %d,"
				       " done = 0x%p, queuecommand 0x%p\n",
					cmd->request_buffer, cmd->request_bufflen,
					cmd->done,
					sdev->host->hostt->queuecommand);

			}
		}
	}
}

void scsi_log_completion(struct scsi_cmnd *cmd, int disposition)
{
	unsigned int level;
	struct scsi_device *sdev;

	/*
	 * If ML COMPLETE log level is greater than or equal to:
	 *
	 * 1: log disposition, result, opcode + command, and conditionally
	 * sense data for failures or non SUCCESS dispositions.
	 *
	 * 2: same as 1 but for all command completions.
	 *
	 * 3: same as 2 plus dump cmd address
	 *
	 * 4: same as 3 plus dump extra junk
	 */
	if (unlikely(scsi_logging_level)) {
		level = SCSI_LOG_LEVEL(SCSI_LOG_MLCOMPLETE_SHIFT,
				       SCSI_LOG_MLCOMPLETE_BITS);
		if (((level > 0) && (cmd->result || disposition != SUCCESS)) ||
		    (level > 1)) {
			sdev = cmd->device;
			sdev_printk(KERN_INFO, sdev, "done ");
			if (level > 2)
				printk("0x%p ", cmd);
			/*
			 * Dump truncated values, so we usually fit within
			 * 80 chars.
			 */
			switch (disposition) {
			case SUCCESS:
				printk("SUCCESS");
				break;
			case NEEDS_RETRY:
				printk("RETRY  ");
				break;
			case ADD_TO_MLQUEUE:
				printk("MLQUEUE");
				break;
			case FAILED:
				printk("FAILED ");
				break;
			case TIMEOUT_ERROR:
				/* 
				 * If called via scsi_times_out.
				 */
				printk("TIMEOUT");
				break;
			default:
				printk("UNKNOWN");
			}
			printk(" %8x ", cmd->result);
			scsi_print_command(cmd);
			if (status_byte(cmd->result) & CHECK_CONDITION) {
				/*
				 * XXX The scsi_print_sense formatting/prefix
				 * doesn't match this function.
				 */
				scsi_print_sense("", cmd);
			}
			if (level > 3) {
				printk(KERN_INFO "scsi host busy %d failed %d\n",
				       sdev->host->host_busy,
				       sdev->host->host_failed);
			}
		}
	}
}
#endif

/* 
 * Assign a serial number and pid to the request for error recovery
 * and debugging purposes.  Protected by the Host_Lock of host.
 */
static inline void scsi_cmd_get_serial(struct Scsi_Host *host, struct scsi_cmnd *cmd)
{
	cmd->serial_number = host->cmd_serial_number++;
	if (cmd->serial_number == 0) 
		cmd->serial_number = host->cmd_serial_number++;
	
	cmd->pid = host->cmd_pid++;
	if (cmd->pid == 0)
		cmd->pid = host->cmd_pid++;
}

/*
 * Function:    scsi_dispatch_command
 *
 * Purpose:     Dispatch a command to the low-level driver.
 *
 * Arguments:   cmd - command block we are dispatching.
 *
 * Notes:
 */
int scsi_dispatch_cmd(struct Scsi_Host *host, struct scsi_device *sdev, struct scsi_cmnd *cmd)
{
	//printf("scsi_dispatch_cmd\n");
	int rtn = 0;

	/* 
	 * If SCSI-2 or lower, store the LUN value in cmnd.
	 */
	if (cmd->cmnd[0] == INQUIRY) 
	{
		cmd->cmnd[1] = (cmd->cmnd[1] & 0x1f) |
			       (cmd->device->lun << 5 & 0xe0);//TODO lun may be should be send in
	}




	//printf("scsi_dispatch_cmd :   cmd->request_bufflen = %d\n",cmd->request_bufflen);
	rtn = host->hostt->queuecommand(cmd, scsi_done);
	return rtn;
}

/**
 * scsi_done - Enqueue the finished SCSI command into the done queue.
 * @cmd: The SCSI Command for which a low-level device driver (LLDD) gives
 * ownership back to SCSI Core -- i.e. the LLDD has finished with it.
 *
 * This function is the mid-level's (SCSI Core) interrupt routine, which
 * regains ownership of the SCSI command (de facto) from a LLDD, and enqueues
 * the command to the done queue for further processing.
 *
 * This is the producer of the done queue who enqueues at the tail.
 *
 * This function is interrupt context safe.
 */
void __scsi_done(struct scsi_cmnd *cmd)
{
}

#if 0
static void scsi_done(struct scsi_cmnd *cmd)
{
	__scsi_done(cmd);
}

/*
 * Function:    scsi_finish_command
 *
 * Purpose:     Pass command off to upper layer for finishing of I/O
 *              request, waking processes that are waiting on results,
 *              etc.
 */
void scsi_finish_command(struct scsi_cmnd *cmd)
{
	struct scsi_device *sdev = cmd->device;
	struct Scsi_Host *shost = sdev->host;

	scsi_device_unbusy(sdev);

        /*
         * Clear the flags which say that the device/host is no longer
         * capable of accepting new commands.  These are set in scsi_queue.c
         * for both the queue full condition on a device, and for a
         * host full condition on the host.
	 *
	 * XXX(hch): What about locking?
         */
        shost->host_blocked = 0;
        sdev->device_blocked = 0;

	/*
	 * If we have valid sense information, then some kind of recovery
	 * must have taken place.  Make a note of this.
	 */
	if (SCSI_SENSE_VALID(cmd))
		cmd->result |= (DRIVER_SENSE << 24);

	SCSI_LOG_MLCOMPLETE(4, sdev_printk(KERN_INFO, sdev,
				"Notifying upper driver of completion "
				"(result %x)\n", cmd->result));

	cmd->done(cmd);
}
#endif








