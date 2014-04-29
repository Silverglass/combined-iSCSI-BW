/*
 *      sd.c Copyright (C) 1992 Drew Eckhardt
 *           Copyright (C) 1993, 1994, 1995, 1999 Eric Youngdale
 *
 *      Linux scsi disk driver
 *              Initial versions: Drew Eckhardt
 *              Subsequent revisions: Eric Youngdale
 *	Modification history:
 *       - Drew Eckhardt <drew@colorado.edu> original
 *       - Eric Youngdale <eric@andante.org> add scatter-gather, multiple 
 *         outstanding request, and other enhancements.
 *         Support loadable low-level scsi drivers.
 *       - Jirka Hanika <geo@ff.cuni.cz> support more scsi disks using 
 *         eight major numbers.
 *       - Richard Gooch <rgooch@atnf.csiro.au> support devfs.
 *	 - Torben Mathiasen <tmm@image.dk> Resource allocation fixes in 
 *	   sd_init and cleanups.
 *	 - Alex Davis <letmein@erols.com> Fix problem where partition info
 *	   not being read in sd_open. Fix problem where removable media 
 *	   could be ejected after sd_open.
 *	 - Douglas Gilbert <dgilbert@interlog.com> cleanup for lk 2.5.x
 *	 - Badari Pulavarty <pbadari@us.ibm.com>, Matthew Wilcox 
 *	   <willy@debian.org>, Kurt Garloff <garloff@suse.de>: 
 *	   Support 32k/1M disks.
 *
 *	Logging policy (needs CONFIG_SCSI_LOGGING defined):
 *	 - setting up transfer: SCSI_LOG_HLQUEUE levels 1 and 2
 *	 - end of transfer (bh + scsi_lib): SCSI_LOG_HLCOMPLETE level 1
 *	 - entering sd_ioctl: SCSI_LOG_IOCTL level 1
 *	 - entering other commands: SCSI_LOG_HLQUEUE level 3
 *	Note: when the logging level is set by the user, it must be greater
 *	than the level indicated above to trigger output.	
 */

#include "sd.h"
#include "scsi.h"
#include "scsi_lib.h"
#include <unistd.h>

uint64_t sd_index;

# define sector_div(n, b)( \
{ \
	int _res; \
	_res = (n) % (b); \
	(n) /= (b); \
	_res; \
} \
)

/*
 * More than enough for everybody ;)  The huge number of majors
 * is a leftover from 16bit dev_t days, we don't really need that
 * much numberspace.
 */
#define SD_MAJORS	16

/*
 * This is limited by the naming scheme enforced in sd_probe,
 * add another character to it if you really need more disks.
 */
#define SD_MAX_DISKS	(((26 * 26) + 26 + 1) * 26)

/*
 * Time out in seconds for disks and Magneto-opticals (which are slower).
 */
#define HZ			800
#define SD_TIMEOUT		(30 * HZ)
#define SD_MOD_TIMEOUT		(75 * HZ)

/*
 * Number of allowed retries
 */
#define SD_MAX_RETRIES		5
#define SD_PASSTHROUGH_RETRIES	1

/*
 * Size of the initial data buffer for mode and read capacity data
 */
#define SD_BUF_SIZE		512


static int media_not_present(struct scsi_sense_hdr *sshdr)
{

	if (!scsi_sense_valid(sshdr))
		return 0;
	/* not invoked for commands that could return deferred errors */
	if (sshdr->sense_key != NOT_READY &&
	    sshdr->sense_key != UNIT_ATTENTION)
		return 0;
	if (sshdr->asc != 0x3A) /* medium not present */
		return 0;

	//set_media_not_present(sdkp);
	return 1;
}

/*
 * spinup disk - called only in sd_revalidate_disk()
 */
static void
sd_spinup_disk(struct scsi_device *sdp, char *diskname)
{
	unsigned char cmd[10];
	uint64_t spintime_expire = 0;
	int retries, spintime;
	unsigned int the_result;
	struct scsi_sense_hdr sshdr;
	int sense_valid = 0;

	spintime = 0;

	/* Spin up drives, as required.  Only do this at boot time */
	/* Spinup needs to be done for module loads too. */
	do {
		retries = 0;

		do {
			cmd[0] = TEST_UNIT_READY;
			memset((void *) &cmd[1], 0, 9);

			the_result = scsi_execute_req(sdp->host, sdp, cmd,
						      DMA_NONE, NULL, 0,
						      &sshdr, SD_TIMEOUT,
						      SD_MAX_RETRIES, 0);

			/*
			 * If the drive has indicated to us that it
			 * doesn't have any media in it, don't bother
			 * with any more polling.
			 */
			if (media_not_present(&sshdr))
				return;

			if (the_result)
				sense_valid = scsi_sense_valid(&sshdr);
			retries++;
		} while (retries < 3 && 
			 (!scsi_status_is_good(the_result) ||
			  ((driver_byte(the_result) & DRIVER_SENSE) &&
			  sense_valid && sshdr.sense_key == UNIT_ATTENTION)));

		if ((driver_byte(the_result) & DRIVER_SENSE) == 0) {
			/* no sense, TUR either succeeded or failed
			 * with a status error */
			if(!spintime && !scsi_status_is_good(the_result))
				printf("%s: Unit Not Ready, "
				       "error = 0x%x\n", diskname, the_result);
			break;
		}
					
		/*
		 * The device does not want the automatic start to be issued.
		 */
		//if (sdkp->device->no_start_on_add) {
		//	break;
		//}

		/*
		 * If manual intervention is required, or this is an
		 * absent USB storage device, a spinup is meaningless.
		 */
		if (sense_valid &&
		    sshdr.sense_key == NOT_READY &&
		    sshdr.asc == 4 && sshdr.ascq == 3) {
			break;		/* manual intervention required */

		/*
		 * Issue command to spin up drive when not ready
		 */
		} else if (sense_valid && sshdr.sense_key == NOT_READY) {
			if (!spintime) {
				printf("%s: Spinning up disk...",
				       diskname);
				cmd[0] = START_STOP;
				cmd[1] = 1;	/* Return immediately */
				memset((void *) &cmd[2], 0, 8);
				cmd[4] = 1;	/* Start spin cycle */
				scsi_execute_req(sdp->host, sdp, cmd, DMA_NONE,
						 NULL, 0, &sshdr,
						 SD_TIMEOUT, SD_MAX_RETRIES, 0);
				spintime_expire = cvmx_get_cycle() + 100 * 800000000;
				spintime = 1;
			}
			/* Wait 1 second for next try */
			cvmx_wait(800000000);
			printf(".");

		/*
		 * Wait for USB flash devices with slow firmware.
		 * Yes, this sense key/ASC combination shouldn't
		 * occur here.  It's characteristic of these devices.
		 */
		} else if (sense_valid &&
				sshdr.sense_key == UNIT_ATTENTION &&
				sshdr.asc == 0x28) {
			if (!spintime) {
				spintime_expire = cvmx_get_cycle() + 5 * 800000000;
				spintime = 1;
			}
			/* Wait 1 second for next try */
			cvmx_wait(800000000);
		} else {
			/* we don't understand the sense code, so it's
			 * probably pointless to loop */
			if(!spintime) {
				printf("%s: Unit Not Ready, "
					"sense:\n", diskname);
				//scsi_print_sense_hdr("", &sshdr);
			}
			break;
		}
				
	} while (spintime && cvmx_get_cycle() > spintime_expire);

	if (spintime) {
		if (scsi_status_is_good(the_result))
			printf("ready\n");
		else
			printf("not responding...\n");
	}
}

/*
 * read disk capacity
 */
static void
sd_read_capacity(struct scsi_device *sdp, char *diskname,
		 unsigned char *buffer)
{
	unsigned char cmd[16];
	int the_result, retries;
	int sector_size = 0;
	int longrc = 0;
	struct scsi_sense_hdr sshdr;
	int sense_valid = 0;
	uint64_t capacity = 0;

repeat:
	retries = 3;
	do {
		if (longrc) {
			memset((void *) cmd, 0, 16);
			cmd[0] = SERVICE_ACTION_IN;
			cmd[1] = SAI_READ_CAPACITY_16;
			cmd[13] = 12;
			memset((void *) buffer, 0, 12);
		} else {
			cmd[0] = READ_CAPACITY;
			memset((void *) &cmd[1], 0, 9);
			memset((void *) buffer, 0, 8);
		}
		
		the_result = scsi_execute_req(sdp->host, sdp, cmd, DMA_FROM_DEVICE,
					      buffer, longrc ? 12 : 8, &sshdr,
					      SD_TIMEOUT, SD_MAX_RETRIES, 0);

		if (media_not_present(&sshdr))
			return;

		if (the_result)
			sense_valid = scsi_sense_valid(&sshdr);
		retries--;

	} while (the_result && retries);

	if (the_result && !longrc) {
		printf("%s : READ CAPACITY failed.\n"
		       "%s : status=%x, message=%02x, host=%d, driver=%02x \n",
		       diskname, diskname,
		       status_byte(the_result),
		       msg_byte(the_result),
		       host_byte(the_result),
		       driver_byte(the_result));

		//if (driver_byte(the_result) & DRIVER_SENSE)
		//	scsi_print_sense_hdr("sd", &sshdr);
		//else
		//	printk("%s : sense not available. \n", diskname);

		/* Set dirty bit for removable devices if not ready -
		 * sometimes drives will not report this properly. */
		if (sdp->removable &&
		    sense_valid && sshdr.sense_key == NOT_READY)
			sdp->changed = 1;

		/* Either no media are present but the drive didn't tell us,
		   or they are present but the read capacity command fails */
		/* sdkp->media_present = 0; -- not always correct */
		//sdkp->capacity = 0; /* unknown mapped to zero - as usual */

		return;
	} else if (the_result && longrc) {
		/* READ CAPACITY(16) has been failed */
		printf("%s : READ CAPACITY(16) failed.\n"
		       "%s : status=%x, message=%02x, host=%d, driver=%02x \n",
		       diskname, diskname,
		       status_byte(the_result),
		       msg_byte(the_result),
		       host_byte(the_result),
		       driver_byte(the_result));
		printf("%s : use 0xffffffff as device size\n",
		       diskname);
		
		capacity = 1 + (sector_t) 0xffffffff;
		printf("capacity is %d\n", capacity);
		goto got_data;
	}	
	
	if (!longrc) {
		sector_size = (buffer[4] << 24) |
			(buffer[5] << 16) | (buffer[6] << 8) | buffer[7];
		if (buffer[0] == 0xff && buffer[1] == 0xff &&
		    buffer[2] == 0xff && buffer[3] == 0xff) {
			if(sizeof(capacity) > 4) {
				printf("%s : very big device. try to use"
				       " READ CAPACITY(16).\n", diskname);
				longrc = 1;
				goto repeat;
			}
			printf("%s: too big for this kernel.  Use a "
			       "kernel compiled with support for large block "
			       "devices.\n", diskname);
			capacity = 0;
			goto got_data;
		}
		capacity = 1 + (((uint64_t)buffer[0] << 24) |
			(buffer[1] << 16) |
			(buffer[2] << 8) |
			buffer[3]);			
	} else {
		capacity = 1 + (((uint64_t)buffer[0] << 56) |
			((uint64_t)buffer[1] << 48) |
			((uint64_t)buffer[2] << 40) |
			((uint64_t)buffer[3] << 32) |
			((uint64_t)buffer[4] << 24) |
			((uint64_t)buffer[5] << 16) |
			((uint64_t)buffer[6] << 8)  |
			(uint64_t)buffer[7]);
			
		sector_size = (buffer[8] << 24) |
			(buffer[9] << 16) | (buffer[10] << 8) | buffer[11];
	}	

	/* Some devices return the total number of sectors, not the
	 * highest sector number.  Make the necessary adjustment. */
	//if (sdp->fix_capacity) {
	//	--sdkp->capacity;

	/* Some devices have version which report the correct sizes
	 * and others which do not. We guess size according to a heuristic
	 * and err on the side of lowering the capacity. */
	//} else {
	//	if (sdp->guess_capacity)
	//		if (sdkp->capacity & 0x01) /* odd sizes are odd */
	//			--sdkp->capacity;
	//}

got_data:
	if (sector_size == 0) {
		sector_size = 512;
		printf("%s : sector size 0 reported, "
		       "assuming 512.\n", diskname);
	}

	if (sector_size != 512 &&
	    sector_size != 1024 &&
	    sector_size != 2048 &&
	    sector_size != 4096 &&
	    sector_size != 256) {
		printf("%s : unsupported sector size "
		       "%d.\n", diskname, sector_size);
		/*
		 * The user might want to re-format the drive with
		 * a supported sectorsize.  Once this happens, it
		 * would be relatively trivial to set the thing up.
		 * For this reason, we leave the thing in the table.
		 */
		capacity = 0;
		/*
		 * set a bogus sector size so the normal read/write
		 * logic in the block layer will eventually refuse any
		 * request on this device without tripping over power
		 * of two sector size assumptions
		 */
		sector_size = 512;
	}
	{
		/*
		 * The msdos fs needs to know the hardware sector size
		 * So I have created this table. See ll_rw_blk.c
		 * Jacques Gelinas (Jacques@solucorp.qc.ca)
		 */
		int hard_sector = sector_size;
		uint64_t sz = (capacity/2) * (hard_sector/256);
		//request_queue_t *queue = sdp->request_queue;
		uint64_t mb = sz;

		//blk_queue_hardsect_size(queue, hard_sector);
		/* avoid 64-bit division on 32-bit platforms */
		sector_div(sz, 625);
		mb -= sz - 974;
		sector_div(mb, 1950);

		printf("SCSI device %s: "
		       "%llu %d-byte hdwr sectors (%llu MB)\n",
		       diskname, (unsigned long long)capacity,
		       hard_sector, (unsigned long long)mb);
	}

	/* Rescale capacity to 512-byte units */
	if (sector_size == 4096)
		capacity <<= 3;
	else if (sector_size == 2048)
		capacity <<= 2;
	else if (sector_size == 1024)
		capacity <<= 1;
	else if (sector_size == 256)
		capacity >>= 1;

	//sdkp->device->sector_size = sector_size;
}

/* called with buffer of length 512 */
static inline int
sd_do_mode_sense(struct scsi_device *sdp, int dbd, int modepage,
		 unsigned char *buffer, int len, struct scsi_mode_data *data,
		 struct scsi_sense_hdr *sshdr)
{
	return scsi_mode_sense(sdp, dbd, modepage, buffer, len,
			       SD_TIMEOUT, SD_MAX_RETRIES, data,
			       sshdr);
}

/*
 * read write protect setting, if possible - called only in sd_revalidate_disk()
 * called with buffer of length SD_BUF_SIZE
 */
static void
sd_read_write_protect_flag(struct scsi_device *sdp, char *diskname,
			   unsigned char *buffer)
{
	int res;
	struct scsi_mode_data data;

	//set_disk_ro(sdkp->disk, 0);
	if (sdp->skip_ms_page_3f) {
		printf("%s: assuming Write Enabled\n", diskname);
		return;
	}

	if (sdp->use_192_bytes_for_3f) {
		res = sd_do_mode_sense(sdp, 0, 0x3F, buffer, 192, &data, NULL);
	} else {
		/*
		 * First attempt: ask for all pages (0x3F), but only 4 bytes.
		 * We have to start carefully: some devices hang if we ask
		 * for more than is available.
		 */
		res = sd_do_mode_sense(sdp, 0, 0x3F, buffer, 4, &data, NULL);

		/*
		 * Second attempt: ask for page 0 When only page 0 is
		 * implemented, a request for page 3F may return Sense Key
		 * 5: Illegal Request, Sense Code 24: Invalid field in
		 * CDB.
		 */
		if (!scsi_status_is_good(res))
			res = sd_do_mode_sense(sdp, 0, 0, buffer, 4, &data, NULL);

		/*
		 * Third attempt: ask 255 bytes, as we did earlier.
		 */
		if (!scsi_status_is_good(res))
			res = sd_do_mode_sense(sdp, 0, 0x3F, buffer, 255,
					       &data, NULL);
	}

	if (!scsi_status_is_good(res)) {
		printf("%s: test WP failed, assume Write Enabled\n", diskname);
	} else {
		//sdkp->write_prot = ((data.device_specific & 0x80) != 0);
		//set_disk_ro(sdkp->disk, sdkp->write_prot);
		printf("%s: Write Protect is %s\n", diskname,
		       ((data.device_specific & 0x80) != 0) ? "on" : "off");
		printf("%s: Mode Sense: %02x %02x %02x %02x\n",
		       diskname, buffer[0], buffer[1], buffer[2], buffer[3]);
	}
}

/*
 * sd_read_cache_type - called only from sd_revalidate_disk()
 * called with buffer of length SD_BUF_SIZE
 */
static void
sd_read_cache_type(struct scsi_device *sdp, char *diskname,
		   unsigned char *buffer)
{
	int len = 0, res;

	int dbd;
	int modepage;
	int WCE;
	int RCD;
	int DPOFUA;
	struct scsi_mode_data data;
	struct scsi_sense_hdr sshdr;

	if (sdp->skip_ms_page_8)
		goto defaults;

	if (sdp->type == TYPE_RBC) {
		modepage = 6;
		dbd = 8;
	} else {
		modepage = 8;
		dbd = 0;
	}

	printf("1 sd_do_mode_sense dbd:%d	modepage:%d,	len:%d\n", dbd, modepage, len);
	/* cautiously ask */
	res = sd_do_mode_sense(sdp, dbd, modepage, buffer, 4, &data, &sshdr);

	if (!scsi_status_is_good(res))
		goto bad_sense;

	if (!data.header_length) {
		modepage = 6;
		printf("%s: missing header in MODE_SENSE response\n",
		       diskname);
	}

	/* that went OK, now ask for the proper length */
	len = data.length;

	/*
	 * We're only interested in the first three bytes, actually.
	 * But the data cache page is defined for the first 20.
	 */
	if (len < 3)
		goto bad_sense;
	if (len > 20)
		len = 20;

	/* Take headers and block descriptors into account */
	len += data.header_length + data.block_descriptor_length;
	if (len > SD_BUF_SIZE)
		goto bad_sense;

	printf("2 sd_do_mode_sense dbd:%d	modepage:%d,	len:%d\n", dbd, modepage, len);
	/* Get the data */
	res = sd_do_mode_sense(sdp, dbd, modepage, buffer, len, &data, &sshdr);

	if (scsi_status_is_good(res)) {
		int offset = data.header_length + data.block_descriptor_length;

		if (offset >= SD_BUF_SIZE - 2) {
			printf("%s: malformed MODE SENSE response",
				diskname);
			goto defaults;
		}

		if ((buffer[offset] & 0x3f) != modepage) {
			printf("%s: got wrong page\n", diskname);
			goto defaults;
		}

		if (modepage == 8) {
			WCE = ((buffer[offset + 2] & 0x04) != 0);
			RCD = ((buffer[offset + 2] & 0x01) != 0);
		} else {
			WCE = ((buffer[offset + 2] & 0x01) == 0);
			RCD = 0;
		}

		DPOFUA = (data.device_specific & 0x10) != 0;
		//if (sdkp->DPOFUA && !sdkp->device->use_10_for_rw) {
		//	printk(KERN_NOTICE "SCSI device %s: uses "
		//	       "READ/WRITE(6), disabling FUA\n", diskname);
		//	sdkp->DPOFUA = 0;
		//}

		printf("SCSI device %s: "
		       "write cache: %s, read cache: %s, %s\n",
		       diskname,
		       WCE ? "enabled" : "disabled",
		       RCD ? "disabled" : "enabled",
		       DPOFUA ? "supports DPO and FUA"
		       : "doesn't support DPO or FUA");

		return;
	}

bad_sense:
	if (scsi_sense_valid(&sshdr) &&
	    sshdr.sense_key == ILLEGAL_REQUEST &&
	    sshdr.asc == 0x24 && sshdr.ascq == 0x0)
		printf("%s: cache data unavailable\n",
		       diskname);	/* Invalid field in CDB */
	else
		printf("%s: asking for cache data failed\n",
		       diskname);

defaults:
	printf("%s: assuming drive cache: write through\n",
	       diskname);
	WCE = 0;
	RCD = 0;
	DPOFUA = 0;
}

/**
 *	sd_revalidate_disk - called the first time a new disk is seen,
 *	performs disk spin up, read_capacity, etc.
 *	@disk: struct gendisk we care about
 **/
static int sd_revalidate_disk(struct scsi_device *sdp, char * disk_name)
{
	unsigned char *buffer;
	unsigned ordered;

	printf("sd_revalidate_disk: disk=%s\n", disk_name);


	buffer = malloc(SD_BUF_SIZE);
	if (!buffer) {
		printf("(sd_revalidate_disk:) Memory allocation "
		       "failure.\n");
		goto out;
	}

	/* defaults, until the device tells us otherwise */
	sdp->sector_size = 512;
	//sdkp->capacity = 0;
	//sdkp->media_present = 1;
	//sdkp->write_prot = 0;
	//sdkp->WCE = 0;
	//sdkp->RCD = 0;

	sd_spinup_disk(sdp, disk_name);

	/*
	 * Without media there is no reason to ask; moreover, some devices
	 * react badly if we do.
	 */
	//if (sdkp->media_present) {
	if(1)
	{
		printf("===============before sd_read_capacity\n");
		sd_read_capacity(sdp, disk_name, buffer);
		printf("===============after sd_read_capacity\n");
		//sd_read_write_protect_flag(sdp, disk_name, buffer);
		//sd_read_cache_type(sdp, disk_name, buffer);
	}

	/*
	 * We now have all cache related info, determine how we deal
	 * with ordered requests.  Note that as the current SCSI
	 * dispatch function can alter request order, we cannot use
	 * QUEUE_ORDERED_TAG_* even when ordered tag is supported.
	 */
	//if (sdkp->WCE)
	//	ordered = sdkp->DPOFUA
	//		? QUEUE_ORDERED_DRAIN_FUA : QUEUE_ORDERED_DRAIN_FLUSH;
	//else
	//	ordered = QUEUE_ORDERED_DRAIN;

	//blk_queue_ordered(sdkp->disk->queue, ordered, sd_prepare_flush);

	//set_capacity(disk, sdkp->capacity);
	free(buffer);

 out:
	return 0;
}

/**
 *	sd_probe - called during driver initialization and whenever a
 *	new scsi device is attached to the system. It is called once
 *	for each scsi device (not just disks) present.
 *	@dev: pointer to device object
 *
 *	Returns 0 if successful (or not interested in this scsi device 
 *	(e.g. scanner)); 1 when there is an error.
 *
 *	Note: this function is invoked from the scsi mid-level.
 *	This function sets up the mapping between a given 
 *	<host,channel,id,lun> (found in sdp) and new device name 
 *	(e.g. /dev/sda). More precisely it is the block device major 
 *	and minor number that is chosen here.
 *
 *	Assume sd_attach is not re-entrant (for time being)
 *	Also think about sd_attach() and sd_remove() running coincidentally.
 **/
int sd_probe(struct scsi_device *sdp)
{
	int error = 0;


	sd_index = sdp->lun;
	if (sd_index >= SD_MAX_DISKS)
		error = -1;
	if (error)
		goto out_put;

	if (!sdp->timeout) {
		if (sdp->type != TYPE_MOD)
			sdp->timeout = SD_TIMEOUT;
		else
			sdp->timeout = SD_MOD_TIMEOUT;
	}

	char disk_name[100];
	memset(disk_name, 0, 100);

	if (sd_index < 26) {
		sprintf(disk_name, "sd%c", 'a' + sd_index % 26);
	} else if (sd_index < (26 + 1) * 26) {
		sprintf(disk_name, "sd%c%c",
			'a' + sd_index / 26 - 1,'a' + sd_index % 26);
	} else {
		const unsigned int m1 = (sd_index / 26 - 1) / 26 - 1;
		const unsigned int m2 = (sd_index / 26 - 1) % 26;
		const unsigned int m3 =  sd_index % 26;
		sprintf(disk_name, "sd%c%c%c",
			'a' + m1, 'a' + m2, 'a' + m3);
	}

	sd_revalidate_disk(sdp, disk_name);
	printf("%d:device address is %X\n", sdp->lun, sdp);

	return 0;

 out_put:
	return error;
}





