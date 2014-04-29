/*
 * scsi_scan.c
 *
 * Copyright (C) 2000 Eric Youngdale,
 * Copyright (C) 2002 Patrick Mansfield
 *
 * The general scanning/probing algorithm is as follows, exceptions are
 * made to it depending on device specific flags, compilation options, and
 * global variable (boot or module load time) settings.
 *
 * A specific LUN is scanned via an INQUIRY command; if the LUN has a
 * device attached, a scsi_device is allocated and setup for it.
 *
 * For every id of every channel on the given host:
 *
 * 	Scan LUN 0; if the target responds to LUN 0 (even if there is no
 * 	device or storage attached to LUN 0):
 *
 * 		If LUN 0 has a device attached, allocate and setup a
 * 		scsi_device for it.
 *
 * 		If target is SCSI-3 or up, issue a REPORT LUN, and scan
 * 		all of the LUNs returned by the REPORT LUN; else,
 * 		sequentially scan LUNs up until some maximum is reached,
 * 		or a LUN is seen that cannot have a device attached to it.
 */

#include "device.h"
#include "scsi.h"
#include "scsi_lib.h"
#include "sd.h"
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


/*
 * Prefix values for the SCSI id's (stored in sysfs name field)
 */
#define SCSI_UID_SER_NUM 'S'
#define SCSI_UID_UNKNOWN 'Z'
#define HZ 800
/*
 * Default timeout
 */
#define SCSI_TIMEOUT (2*HZ)
static unsigned int scsi_inq_timeout = SCSI_TIMEOUT/HZ+3;

/*
 * Return values of some of the scanning functions.
 *
 * SCSI_SCAN_NO_RESPONSE: no valid response received from the target, this
 * includes allocation or general failures preventing IO from being sent.
 *
 * SCSI_SCAN_TARGET_PRESENT: target responded, but no device is available
 * on the given LUN.
 *
 * SCSI_SCAN_LUN_PRESENT: target responded, and a device is available on a
 * given LUN.
 */
#define SCSI_SCAN_NO_RESPONSE		0
#define SCSI_SCAN_TARGET_PRESENT	1
#define SCSI_SCAN_LUN_PRESENT		2

static const char *scsi_null_device_strs = "nullnullnullnull";

#define MAX_SCSI_LUNS	512

static unsigned int max_scsi_luns = MAX_SCSI_LUNS;

#define SCSI_SCAN_TYPE_DEFAULT "sync"

#define min(x,y) ((x)<(y)?(x):(y))

#define max_t(type,x,y) \
	({ type __x = (x); type __y = (y); __x > __y ? __x: __y; })

static char scsi_scan_type[6] = SCSI_SCAN_TYPE_DEFAULT;

/*
 * max_scsi_report_luns: the maximum number of LUNS that will be
 * returned from the REPORT LUNS command. 8 times this value must
 * be allocated. In theory this could be up to an 8 byte value, but
 * in practice, the maximum number of LUNs suppored by any device
 * is about 16k.
 */
static unsigned int max_scsi_report_luns = 511;

/**
 * scsi_unlock_floptical - unlock device via a special MODE SENSE command
 * @sdev:	scsi device to send command to
 * @result:	area to store the result of the MODE SENSE
 *
 * Description:
 *     Send a vendor specific MODE SENSE (not a MODE SELECT) command.
 *     Called for BLIST_KEY devices.
 **/
static void scsi_unlock_floptical(struct Scsi_Host *shost, struct scsi_device *sdev,
				  unsigned char *result)
{
	unsigned char scsi_cmd[MAX_COMMAND_SIZE];

	printf("scsi: unlocking floptical drive\n");
	scsi_cmd[0] = MODE_SENSE;
	scsi_cmd[1] = 0;
	scsi_cmd[2] = 0x2e;
	scsi_cmd[3] = 0;
	scsi_cmd[4] = 0x2a;     /* size */
	scsi_cmd[5] = 0;
	scsi_execute_req(shost, sdev, scsi_cmd, DMA_FROM_DEVICE, result, 0x2a, NULL,
			 SCSI_TIMEOUT, 3, 0);
}

/**
 * scsi_alloc_sdev - allocate and setup a scsi_Device
 *
 * Description:
 *     Allocate, initialize for io, and return a pointer to a scsi_Device.
 *     Stores the @shost, @channel, @id, and @lun in the scsi_Device, and
 *     adds scsi_Device to the appropriate list.
 *
 * Return value:
 *     scsi_Device pointer, or NULL on failure.
 **/
static struct scsi_device *scsi_alloc_sdev(struct Scsi_Host *shost, struct scsi_target *starget,
					   unsigned int lun, void *hostdata)
{
	struct scsi_device *sdev;
	int display_failure_msg = 1;

	sdev = cvm_common_alloc_fpa_buffer_sync(CVMX_FPA_PACKET_POOL);
	if (!sdev)
		goto out;
	printf("alloc sdev , address is %p\n", sdev);
	memset(sdev, 0, sizeof(*sdev));

	sdev->vendor = scsi_null_device_strs;
	sdev->model = scsi_null_device_strs;
	sdev->rev = scsi_null_device_strs;
	sdev->host = shost;
	sdev->id = starget->id;
	sdev->lun = lun;
	sdev->channel = starget->channel;
	sdev->sdev_state = SDEV_CREATED;
	INIT_LIST_HEAD(&sdev->siblings);
        INIT_LIST_HEAD(&sdev->same_target_siblings);
        INIT_LIST_HEAD(&sdev->cmd_list);
        INIT_LIST_HEAD(&sdev->starved_entry);

	sdev->sdev_target = starget;

	/* usually NULL and set by ->slave_alloc instead */
	sdev->hostdata = hostdata;

	/* if the device needs this changing, it may do so in the
	 * slave_configure function */
	sdev->max_device_blocked = SCSI_DEFAULT_DEVICE_BLOCKED;

	/*
	 * Some low level driver could use device->type
	 */
	sdev->type = -1;

	/*
	 * Assume that the device will have handshaking problems,
	 * and then fix this field later if it turns out it
	 * doesn't
	 */
	sdev->borken = 1;

	
	//scsi_sysfs_device_initialize(sdev);
	{
		struct Scsi_Host *shost = sdev->host;
		struct scsi_target  *starget = sdev->sdev_target;

		sdev->scsi_level = starget->scsi_level;
		list_add_tail(&sdev->same_target_siblings, &starget->devices);
		list_add_tail(&sdev->siblings, &shost->__devices);
	}

	printf("sdev->inquiry_len is %d\n", sdev->inquiry_len);	

	return sdev;

out:
	if (display_failure_msg)
		printf("display_failure_msg:%d\n", display_failure_msg);
	return NULL;
}


/**
 * scsi_alloc_target - allocate a new or find an existing target
 * @parent:	parent of the target (need not be a scsi host)
 * @channel:	target channel number (zero if no channels)
 * @id:		target id number
 *
 * Return an existing target if one exists, provided it hasn't already
 * gone into STARGET_DEL state, otherwise allocate a new target.
 *
 * The target is returned with an incremented reference, so the caller
 * is responsible for both reaping and doing a last put
 */
static struct scsi_target *scsi_alloc_target(struct Scsi_Host *shost,
					     int channel, uint id)
{
	//struct device *dev = NULL;
	const int size = sizeof(struct scsi_target);
	struct scsi_target *starget;

	starget = malloc(size);
	if (!starget) {
		printf("%s: allocation failure\n", __FUNCTION__);
		return NULL;
	}
	//dev = &starget->dev;
	starget->reap_ref = 1;
	//dev->parent = get_device(parent);
	//dev->release = scsi_target_dev_release;
	//sprintf(dev->bus_id, "target%d:%d:%d",
	//	shost->host_no, channel, id);
	starget->id = id;
	starget->channel = channel;
	INIT_LIST_HEAD(&starget->siblings);
	INIT_LIST_HEAD(&starget->devices);
	starget->state = STARGET_RUNNING;
	starget->scsi_level = SCSI_2;

	list_add_tail(&starget->siblings, &shost->__targets);

	return starget;
}


/**
 * sanitize_inquiry_string - remove non-graphical chars from an INQUIRY result string
 * @s: INQUIRY result string to sanitize
 * @len: length of the string
 *
 * Description:
 *	The SCSI spec says that INQUIRY vendor, product, and revision
 *	strings must consist entirely of graphic ASCII characters,
 *	padded on the right with spaces.  Since not all devices obey
 *	this rule, we will replace non-graphic or non-ASCII characters
 *	with spaces.  Exception: a NUL character is interpreted as a
 *	string terminator, so all the following characters are set to
 *	spaces.
 **/
static void sanitize_inquiry_string(unsigned char *s, int len)
{
	int terminated = 0;

	for (; len > 0; (--len, ++s)) {
		if (*s == 0)
			terminated = 1;
		if (terminated || *s < 0x20 || *s > 0x7e)
			*s = ' ';
	}
}



/*static inline int scsi_sense_valid(struct scsi_sense_hdr *sshdr)
{
	if (!sshdr)
		return 0;

	return (sshdr->response_code & 0x70) == 0x70;
}*/



/**
 * scsi_probe_lun - probe a single LUN using a SCSI INQUIRY
 * @sdev:	scsi_device to probe
 * @inq_result:	area to store the INQUIRY result
 * @result_len: len of inq_result
 * @bflags:	store any bflags found here
 *
 * Description:
 *     Probe the lun associated with @req using a standard SCSI INQUIRY;
 *
 *     If the INQUIRY is successful, zero is returned and the
 *     INQUIRY data is in @inq_result; the scsi_level and INQUIRY length
 *     are copied to the scsi_device any flags value is stored in *@bflags.
 **/
static int scsi_probe_lun(struct Scsi_Host *shost, struct scsi_device *sdev, unsigned char *inq_result,
			  int result_len, int *bflags)
{
	printf("scsi_probe_lun\n");
	unsigned char scsi_cmd[MAX_COMMAND_SIZE];
	int first_inquiry_len, try_inquiry_len, next_inquiry_len;
	int response_len = 0;
	int pass, count, result;
	struct scsi_sense_hdr sshdr;

	*bflags = 0;

	/* Perform up to 3 passes.  The first pass uses a conservative
	 * transfer length of 36 unless sdev->inquiry_len specifies a
	 * different value. */
	first_inquiry_len = sdev->inquiry_len ? sdev->inquiry_len : 36;
	try_inquiry_len = first_inquiry_len;
	pass = 1;

 next_pass:
	/* Each pass gets up to three chances to ignore Unit Attention */
	for (count = 0; count < 3; ++count) {
		memset(scsi_cmd, 0, MAX_COMMAND_SIZE);
		scsi_cmd[0] = INQUIRY;
		scsi_cmd[4] = (unsigned char) try_inquiry_len;

		memset(inq_result, 0, try_inquiry_len);

		//TODO scsi_execute_req
		result = scsi_execute_req(shost, sdev,  scsi_cmd, DMA_FROM_DEVICE,
					  inq_result, try_inquiry_len, &sshdr,
					  HZ / 2 + HZ * scsi_inq_timeout, 3, 0);
		printf("+++++++++++++++++++:%d\n", result);
		if (result) {
			/*
			 * not-ready to ready transition [asc/ascq=0x28/0x0]
			 * or power-on, reset [asc/ascq=0x29/0x0], continue.
			 * INQUIRY should not yield UNIT_ATTENTION
			 * but many buggy devices do so anyway. 
			 */
			if ((driver_byte(result) & DRIVER_SENSE) &&
			    scsi_sense_valid(&sshdr)) {
				if ((sshdr.sense_key == UNIT_ATTENTION) &&
				    ((sshdr.asc == 0x28) ||
				     (sshdr.asc == 0x29)) &&
				    (sshdr.ascq == 0))
					continue;
			}
		}
		break;
	}
	printf("-------------------------------\n");
	if (result == 0) {
		sanitize_inquiry_string(&inq_result[8], 8);
		sanitize_inquiry_string(&inq_result[16], 16);
		sanitize_inquiry_string(&inq_result[32], 4);

		response_len = inq_result[4] + 5;
		if (response_len > 255)
			response_len = first_inquiry_len;	/* sanity */

		/*
		 * Get any flags for this device.
		 *
		 * XXX add a bflags to scsi_device, and replace the
		 * corresponding bit fields in scsi_device, so bflags
		 * need not be passed as an argument.
		 */
		//TODO *bflags may be not always 0
		*bflags = 0;

		/* When the first pass succeeds we gain information about
		 * what larger transfer lengths might work. */
		if (pass == 1) {
			if (BLIST_INQUIRY_36 & *bflags)
			{
				printf("1\n");
				next_inquiry_len = 36;
			}
			else if (BLIST_INQUIRY_58 & *bflags)
			{
				printf("2\n");
				next_inquiry_len = 58;
			}
			else if (sdev->inquiry_len)
			{
				printf("3\n");
				next_inquiry_len = sdev->inquiry_len;
			}
			else
			{
				printf("response_len is %d\n", response_len);
				next_inquiry_len = response_len;
			}

			printf("next_inquiry_len is %d\n", next_inquiry_len);
			/* If more data is available perform the second pass */
			if (next_inquiry_len > try_inquiry_len) {
				printf("try_inquiry_len is %d\n", next_inquiry_len);
				try_inquiry_len = next_inquiry_len;
				pass = 2;
				goto next_pass;
			}
		}

	} else if (pass == 2) {
		printf("scsi scan: %d byte inquiry failed.  Consider BLIST_INQUIRY_36 for this device\n", try_inquiry_len);

		/* If this pass failed, the third pass goes back and transfers
		 * the same amount as we successfully got in the first pass. */
		try_inquiry_len = first_inquiry_len;
		pass = 3;
		goto next_pass;
	}

	/* If the last transfer attempt got an error, assume the
	 * peripheral doesn't exist or is dead. */
	if (result)
		return -1;

	/* Don't report any more data than the device says is valid */
	sdev->inquiry_len = min(try_inquiry_len, response_len);

	/*
	 * XXX Abort if the response length is less than 36? If less than
	 * 32, the lookup of the device flags (above) could be invalid,
	 * and it would be possible to take an incorrect action - we do
	 * not want to hang because of a short INQUIRY. On the flip side,
	 * if the device is spun down or becoming ready (and so it gives a
	 * short INQUIRY), an abort here prevents any further use of the
	 * device, including spin up.
	 *
	 * On the whole, the best approach seems to be to assume the first
	 * 36 bytes are valid no matter what the device says.  That's
	 * better than copying < 36 bytes to the inquiry-result buffer
	 * and displaying garbage for the Vendor, Product, or Revision
	 * strings.
	 */
	if (sdev->inquiry_len < 36) {
		printf("scsi scan: INQUIRY result too short (%d), using 36\n", sdev->inquiry_len);
		sdev->inquiry_len = 36;
	}

	/*
	 * Related to the above issue:
	 *
	 * XXX Devices (disk or all?) should be sent a TEST UNIT READY,
	 * and if not ready, sent a START_STOP to start (maybe spin up) and
	 * then send the INQUIRY again, since the INQUIRY can change after
	 * a device is initialized.
	 *
	 * Ideally, start a device if explicitly asked to do so.  This
	 * assumes that a device is spun up on power on, spun down on
	 * request, and then spun up on request.
	 */

	/*
	 * The scanning code needs to know the scsi_level, even if no
	 * device is attached at LUN 0 (SCSI_SCAN_TARGET_PRESENT) so
	 * non-zero LUNs can be scanned.
	 */
	sdev->scsi_level = inq_result[2] & 0x07;
	if (sdev->scsi_level >= 2 ||
	    (sdev->scsi_level == 1 && (inq_result[3] & 0x0f) == 1))
		sdev->scsi_level++;
	sdev->sdev_target->scsi_level = sdev->scsi_level;
	printf("sdev->scsi_level is %d\n", sdev->scsi_level);

	return 0;
}

/**
 * scsi_add_lun - allocate and fully initialze a scsi_device
 * @sdevscan:	holds information to be stored in the new scsi_device
 * @sdevnew:	store the address of the newly allocated scsi_device
 * @inq_result:	holds the result of a previous INQUIRY to the LUN
 * @bflags:	black/white list flag
 *
 * Description:
 *     Allocate and initialize a scsi_device matching sdevscan. Optionally
 *     set fields based on values in *@bflags. If @sdevnew is not
 *     NULL, store the address of the new scsi_device in *@sdevnew (needed
 *     when scanning a particular LUN).
 *
 * Return:
 *     SCSI_SCAN_NO_RESPONSE: could not allocate or setup a scsi_device
 *     SCSI_SCAN_LUN_PRESENT: a new scsi_device was allocated and initialized
 **/
static int scsi_add_lun(struct scsi_device *sdev, unsigned char *inq_result,
		int *bflags, int async)
{
	printf("scsi_add_lun\n");
	/*
	 * XXX do not save the inquiry, since it can change underneath us,
	 * save just vendor/model/rev.
	 *
	 * Rather than save it and have an ioctl that retrieves the saved
	 * value, have an ioctl that executes the same INQUIRY code used
	 * in scsi_probe_lun, let user level programs doing INQUIRY
	 * scanning run at their own risk, or supply a user level program
	 * that can correctly scan.
	 */

	/*
	 * Copy at least 36 bytes of INQUIRY data, so that we don't
	 * dereference unallocated memory when accessing the Vendor,
	 * Product, and Revision strings.  Badly behaved devices may set
	 * the INQUIRY Additional Length byte to a small value, indicating
	 * these strings are invalid, but often they contain plausible data
	 * nonetheless.  It doesn't matter if the device sent < 36 bytes
	 * total, since scsi_probe_lun() initializes inq_result with 0s.
	 */
	sdev->inquiry = malloc(max_t(size_t, sdev->inquiry_len, 36));
	memcpy(sdev->inquiry, inq_result, max_t(size_t, sdev->inquiry_len, 36));
	if (sdev->inquiry == NULL)
		return SCSI_SCAN_NO_RESPONSE;

	sdev->vendor = (char *) (sdev->inquiry + 8);
	sdev->model = (char *) (sdev->inquiry + 16);
	sdev->rev = (char *) (sdev->inquiry + 32);

	if (*bflags & BLIST_ISROM) {
		/*
		 * It would be better to modify sdev->type, and set
		 * sdev->removable; this can now be done since
		 * print_inquiry has gone away.
		 */
		inq_result[0] = TYPE_ROM;
		inq_result[1] |= 0x80;	/* removable */
	} else if (*bflags & BLIST_NO_ULD_ATTACH)
		sdev->no_uld_attach = 1;

	switch (sdev->type = (inq_result[0] & 0x1f)) {
	case TYPE_RBC:
		/* RBC devices can return SCSI-3 compliance and yet
		 * still not support REPORT LUNS, so make them act as
		 * BLIST_NOREPORTLUN unless BLIST_REPORTLUN2 is
		 * specifically set */
		if ((*bflags & BLIST_REPORTLUN2) == 0)
			*bflags |= BLIST_NOREPORTLUN;
		/* fall through */
	case TYPE_TAPE:
	case TYPE_DISK:
	case TYPE_PRINTER:
	case TYPE_MOD:
	case TYPE_PROCESSOR:
	case TYPE_SCANNER:
	case TYPE_MEDIUM_CHANGER:
	case TYPE_ENCLOSURE:
	case TYPE_COMM:
	case TYPE_RAID:
		sdev->writeable = 1;
		break;
	case TYPE_ROM:
		/* MMC devices can return SCSI-3 compliance and yet
		 * still not support REPORT LUNS, so make them act as
		 * BLIST_NOREPORTLUN unless BLIST_REPORTLUN2 is
		 * specifically set */
		if ((*bflags & BLIST_REPORTLUN2) == 0)
			*bflags |= BLIST_NOREPORTLUN;
		/* fall through */
	case TYPE_WORM:
		sdev->writeable = 0;
		break;
	default:
		printf("scsi: unknown device type %d\n", sdev->type);
	}

	/*
	 * For a peripheral qualifier (PQ) value of 1 (001b), the SCSI
	 * spec says: The device server is capable of supporting the
	 * specified peripheral device type on this logical unit. However,
	 * the physical device is not currently connected to this logical
	 * unit.
	 *
	 * The above is vague, as it implies that we could treat 001 and
	 * 011 the same. Stay compatible with previous code, and create a
	 * scsi_device for a PQ of 1
	 *
	 * Don't set the device offline here; rather let the upper
	 * level drivers eval the PQ to decide whether they should
	 * attach. So remove ((inq_result[0] >> 5) & 7) == 1 check.
	 */ 

	sdev->inq_periph_qual = (inq_result[0] >> 5) & 7;
	sdev->removable = (0x80 & inq_result[1]) >> 7;
	sdev->lockable = sdev->removable;
	sdev->soft_reset = (inq_result[7] & 1) && ((inq_result[3] & 7) == 2);

	if (sdev->scsi_level >= SCSI_3 || (sdev->inquiry_len > 56 &&
		inq_result[56] & 0x04))
		sdev->ppr = 1;
	if (inq_result[7] & 0x60)
		sdev->wdtr = 1;
	if (inq_result[7] & 0x10)
		sdev->sdtr = 1;

	/*
	 * End sysfs code.
	 */

	if ((sdev->scsi_level >= SCSI_2) && (inq_result[7] & 2) &&
	    !(*bflags & BLIST_NOTQ))
		sdev->tagged_supported = 1;
	/*
	 * Some devices (Texel CD ROM drives) have handshaking problems
	 * when used with the Seagate controllers. borken is initialized
	 * to 1, and then set it to 0 here.
	 */
	if ((*bflags & BLIST_BORKEN) == 0)
		sdev->borken = 0;

	/*
	 * Apparently some really broken devices (contrary to the SCSI
	 * standards) need to be selected without asserting ATN
	 */
	if (*bflags & BLIST_SELECT_NO_ATN)
		sdev->select_no_atn = 1;

	/*
	 * Maximum 512 sector transfer length
	 * broken RA4x00 Compaq Disk Array
	 */
	//if (*bflags & BLIST_MAX_512)
	//	blk_queue_max_sectors(sdev->request_queue, 512);

	/*
	 * Some devices may not want to have a start command automatically
	 * issued when a device is added.
	 */
	if (*bflags & BLIST_NOSTARTONADD)
		sdev->no_start_on_add = 1;

	if (*bflags & BLIST_SINGLELUN)
		sdev->single_lun = 1;


	sdev->use_10_for_rw = 1;

	if (*bflags & BLIST_MS_SKIP_PAGE_08)
		sdev->skip_ms_page_8 = 1;

	if (*bflags & BLIST_MS_SKIP_PAGE_3F)
		sdev->skip_ms_page_3f = 1;

	if (*bflags & BLIST_USE_10_BYTE_MS)
		sdev->use_10_for_ms = 1;

	/* set the device running here so that slave configure
	 * may do I/O */
	scsi_device_set_state(sdev, SDEV_RUNNING);

	if (*bflags & BLIST_MS_192_BYTES_FOR_3F)
		sdev->use_192_bytes_for_3f = 1;

	if (*bflags & BLIST_NOT_LOCKABLE)
		sdev->lockable = 0;

	if (*bflags & BLIST_RETRY_HWERROR)
		sdev->retry_hwerror = 1;

	//transport_configure_device(&sdev->sdev_gendev);

	//TODO make sure the slave_configure function is pass by iSCSI
	if (sdev->host->hostt->slave_configure) {
		int ret = sdev->host->hostt->slave_configure(sdev);
		if (ret) {
			/*
			 * if LLDD reports slave not present, don't clutter
			 * console with alloc failure messages
			 */
			printf("slave_configure is wrong!\n");
			return SCSI_SCAN_NO_RESPONSE;
		}
	}

	/*
	 * Ok, the device is now all set up, we can
	 * register it and tell the rest of the kernel
	 * about it.
	 */
	//if (!async && scsi_sysfs_add_sdev(sdev) != 0)
	//	return SCSI_SCAN_NO_RESPONSE;
	printf("sd_probe is going to run!\n");
	sd_probe(sdev);

	return SCSI_SCAN_LUN_PRESENT;
}

static inline void scsi_destroy_sdev(struct scsi_device *sdev)
{
	scsi_device_set_state(sdev, SDEV_DEL);
	if (sdev->host->hostt->slave_destroy)
		sdev->host->hostt->slave_destroy(sdev);
}

#ifdef CONFIG_SCSI_LOGGING
/** 
 * scsi_inq_str - print INQUIRY data from min to max index,
 * strip trailing whitespace
 * @buf:   Output buffer with at least end-first+1 bytes of space
 * @inq:   Inquiry buffer (input)
 * @first: Offset of string into inq
 * @end:   Index after last character in inq
 */
static unsigned char *scsi_inq_str(unsigned char *buf, unsigned char *inq,
				   unsigned first, unsigned end)
{
	unsigned term = 0, idx;

	for (idx = 0; idx + first < end && idx + first < inq[4] + 5; idx++) {
		if (inq[idx+first] > ' ') {
			buf[idx] = inq[idx+first];
			term = idx+1;
		} else {
			buf[idx] = ' ';
		}
	}
	buf[term] = 0;
	return buf;
}
#endif

/**
 * scsi_probe_and_add_lun - probe a LUN, if a LUN is found add it
 * @starget:	pointer to target device structure
 * @lun:	LUN of target device
 * @sdevscan:	probe the LUN corresponding to this scsi_device
 * @sdevnew:	store the value of any new scsi_device allocated
 * @bflagsp:	store bflags here if not NULL
 *
 * Description:
 *     Call scsi_probe_lun, if a LUN with an attached device is found,
 *     allocate and set it up by calling scsi_add_lun.
 *
 * Return:
 *     SCSI_SCAN_NO_RESPONSE: could not allocate or setup a scsi_device
 *     SCSI_SCAN_TARGET_PRESENT: target responded, but no device is
 *         attached at the LUN
 *     SCSI_SCAN_LUN_PRESENT: a new scsi_device was allocated and initialized
 **/
static int scsi_probe_and_add_lun(struct Scsi_Host *shost, struct scsi_target *starget,
				  uint lun, int *bflagsp,
				  struct scsi_device **sdevp, int rescan,
				  void *hostdata)
{
	printf("scsi_probe_and_add_lun\n");
	struct scsi_device *sdev;
	unsigned char *result;
	int bflags, res = SCSI_SCAN_NO_RESPONSE, result_len = 256;

	/*
	 * The rescan flag is used as an optimization, the first scan of a
	 * host adapter calls into here with rescan == 0.
	 */
	sdev = scsi_device_lookup_by_target(shost, starget, lun);
	if (sdev) {
		if (rescan || sdev->sdev_state != SDEV_CREATED) {
			printf("scsi scan: device exists on\n");
			if (sdevp)
				*sdevp = sdev;

			if (bflagsp)
				*bflagsp = 0;

			return SCSI_SCAN_LUN_PRESENT;
		}
	} else
		sdev = scsi_alloc_sdev(shost, starget, lun, hostdata);
	if (!sdev)
		goto out;
	printf("sdev address is %X\n", sdev);
	printf("sdev->lun is %d\n", sdev->lun);

	result = malloc(result_len);
	if (!result)
		goto out_free_sdev;

	if (scsi_probe_lun(shost, sdev, result, result_len, &bflags))
		goto out_free_result;

	printf("After scsi_probe_lun!\n");
	if (bflagsp)
		*bflagsp = bflags;
	/*
	 * result contains valid SCSI INQUIRY data.
	 */
	if (((result[0] >> 5) == 3) && !(bflags & BLIST_ATTACH_PQ3)) {
		/*
		 * For a Peripheral qualifier 3 (011b), the SCSI
		 * spec says: The device server is not capable of
		 * supporting a physical device on this logical
		 * unit.
		 *
		 * For disks, this implies that there is no
		 * logical disk configured at sdev->lun, but there
		 * is a target id responding.
		 */
		if (lun == 0) {
		}
		
		res = SCSI_SCAN_TARGET_PRESENT;
		goto out_free_result;
	}

	/*
	 * Some targets may set slight variations of PQ and PDT to signal
	 * that no LUN is present, so don't add sdev in these cases.
	 * Two specific examples are:
	 * 1) NetApp targets: return PQ=1, PDT=0x1f
	 * 2) USB UFI: returns PDT=0x1f, with the PQ bits being "reserved"
	 *    in the UFI 1.0 spec (we cannot rely on reserved bits).
	 *
	 * References:
	 * 1) SCSI SPC-3, pp. 145-146
	 * PQ=1: "A peripheral device having the specified peripheral
	 * device type is not connected to this logical unit. However, the
	 * device server is capable of supporting the specified peripheral
	 * device type on this logical unit."
	 * PDT=0x1f: "Unknown or no device type"
	 * 2) USB UFI 1.0, p. 20
	 * PDT=00h Direct-access device (floppy)
	 * PDT=1Fh none (no FDD connected to the requested logical unit)
	 */
	if (((result[0] >> 5) == 1 || starget->pdt_1f_for_no_lun) &&
	     (result[0] & 0x1f) == 0x1f) {
		printf("scsi scan: peripheral device type of 31, no device added\n");
		res = SCSI_SCAN_TARGET_PRESENT;
		goto out_free_result;
	}
	printf("before scsi_add_lun!\n");
	res = scsi_add_lun(sdev, result, &bflags, shost->async_scan);
	if (res == SCSI_SCAN_LUN_PRESENT) {
		if (bflags & BLIST_KEY) {
			sdev->lockable = 0;
			scsi_unlock_floptical(shost, sdev, result);
		}
	}
	printf("after scsi_add_lun\n");

out_free_result:
	free(result);
out_free_sdev:
	if (res == SCSI_SCAN_LUN_PRESENT) 
	{
		if (sdevp) 
		{
			*sdevp = sdev;
		}
	} else
		//TODO should make sure the process of the scsi_destroy_sdev
		scsi_destroy_sdev(sdev);
out:
	return res;
}

/**
 * scsi_sequential_lun_scan - sequentially scan a SCSI target
 * @starget:	pointer to target structure to scan
 * @bflags:	black/white list flag for LUN 0
 *
 * Description:
 *     Generally, scan from LUN 1 (LUN 0 is assumed to already have been
 *     scanned) to some maximum lun until a LUN is found with no device
 *     attached. Use the bflags to figure out any oddities.
 *
 *     Modifies sdevscan->lun.
 **/
static void scsi_sequential_lun_scan(struct Scsi_Host *shost, struct scsi_target *starget,
				     int bflags, int scsi_level, int rescan)
{
	unsigned int sparse_lun, lun, max_dev_lun;

	printf("scsi scan: Sequential scan of\n");

	max_dev_lun = min(max_scsi_luns, shost->max_lun);
	/*
	 * If this device is known to support sparse multiple units,
	 * override the other settings, and scan all of them. Normally,
	 * SCSI-3 devices should be scanned via the REPORT LUNS.
	 */
	if (bflags & BLIST_SPARSELUN) {
		max_dev_lun = shost->max_lun;
		sparse_lun = 1;
	} else
		sparse_lun = 0;

	/*
	 * If less than SCSI_1_CSS, and no special lun scaning, stop
	 * scanning; this matches 2.4 behaviour, but could just be a bug
	 * (to continue scanning a SCSI_1_CSS device).
	 *
	 * This test is broken.  We might not have any device on lun0 for
	 * a sparselun device, and if that's the case then how would we
	 * know the real scsi_level, eh?  It might make sense to just not
	 * scan any SCSI_1 device for non-0 luns, but that check would best
	 * go into scsi_alloc_sdev() and just have it return null when asked
	 * to alloc an sdev for lun > 0 on an already found SCSI_1 device.
	 *
	if ((sdevscan->scsi_level < SCSI_1_CCS) &&
	    ((bflags & (BLIST_FORCELUN | BLIST_SPARSELUN | BLIST_MAX5LUN))
	     == 0))
		return;
	 */
	/*
	 * If this device is known to support multiple units, override
	 * the other settings, and scan all of them.
	 */
	if (bflags & BLIST_FORCELUN)
		max_dev_lun = shost->max_lun;
	/*
	 * REGAL CDC-4X: avoid hang after LUN 4
	 */
	if (bflags & BLIST_MAX5LUN)
		max_dev_lun = min(5U, max_dev_lun);
	/*
	 * Do not scan SCSI-2 or lower device past LUN 7, unless
	 * BLIST_LARGELUN.
	 */
	if (scsi_level < SCSI_3 && !(bflags & BLIST_LARGELUN))
		max_dev_lun = min(8U, max_dev_lun);

	/*
	 * We have already scanned LUN 0, so start at LUN 1. Keep scanning
	 * until we reach the max, or no LUN is found and we are not
	 * sparse_lun.
	 */
	for (lun = 1; lun < max_dev_lun; ++lun)
		if ((scsi_probe_and_add_lun(shost, starget, lun, NULL, NULL, rescan,
					    NULL) != SCSI_SCAN_LUN_PRESENT) &&
		    !sparse_lun)
			return;
}

/**
 * scsilun_to_int: convert a scsi_lun to an int
 * @scsilun:	struct scsi_lun to be converted.
 *
 * Description:
 *     Convert @scsilun from a struct scsi_lun to a four byte host byte-ordered
 *     integer, and return the result. The caller must check for
 *     truncation before using this function.
 *
 * Notes:
 *     The struct scsi_lun is assumed to be four levels, with each level
 *     effectively containing a SCSI byte-ordered (big endian) short; the
 *     addressing bits of each level are ignored (the highest two bits).
 *     For a description of the LUN format, post SCSI-3 see the SCSI
 *     Architecture Model, for SCSI-3 see the SCSI Controller Commands.
 *
 *     Given a struct scsi_lun of: 0a 04 0b 03 00 00 00 00, this function returns
 *     the integer: 0x0b030a04
 **/
static int scsilun_to_int(struct scsi_lun *scsilun)
{
	int i;
	unsigned int lun;

	lun = 0;
	for (i = 0; i < sizeof(lun); i += 2)
		lun = lun | (((scsilun->scsi_lun[i] << 8) |
			      scsilun->scsi_lun[i + 1]) << (i * 8));
	return lun;
}

/**
 * int_to_scsilun: reverts an int into a scsi_lun
 * @int:        integer to be reverted
 * @scsilun:	struct scsi_lun to be set.
 *
 * Description:
 *     Reverts the functionality of the scsilun_to_int, which packed
 *     an 8-byte lun value into an int. This routine unpacks the int
 *     back into the lun value.
 *     Note: the scsilun_to_int() routine does not truly handle all
 *     8bytes of the lun value. This functions restores only as much
 *     as was set by the routine.
 *
 * Notes:
 *     Given an integer : 0x0b030a04,  this function returns a
 *     scsi_lun of : struct scsi_lun of: 0a 04 0b 03 00 00 00 00
 *
 **/
void int_to_scsilun(unsigned int lun, struct scsi_lun *scsilun)
{
	int i;

	memset(scsilun->scsi_lun, 0, sizeof(scsilun->scsi_lun));

	for (i = 0; i < sizeof(lun); i += 2) {
		scsilun->scsi_lun[i] = (lun >> 8) & 0xFF;
		scsilun->scsi_lun[i+1] = lun & 0xFF;
		lun = lun >> 16;
	}
}

/**
 * scsi_report_lun_scan - Scan using SCSI REPORT LUN results
 * @sdevscan:	scan the host, channel, and id of this scsi_device
 *
 * Description:
 *     If @sdevscan is for a SCSI-3 or up device, send a REPORT LUN
 *     command, and scan the resulting list of LUNs by calling
 *     scsi_probe_and_add_lun.
 *
 *     Modifies sdevscan->lun.
 *
 * Return:
 *     0: scan completed (or no memory, so further scanning is futile)
 *     1: no report lun scan, or not configured
 **/
static int scsi_report_lun_scan(struct Scsi_Host *shost, struct scsi_target *starget, int bflags,
				int rescan)
{
	printf("scsi_report_lun_scan\n");
	char devname[64];
	unsigned char scsi_cmd[MAX_COMMAND_SIZE];
	unsigned int length;
	unsigned int lun;
	unsigned int num_luns;
	unsigned int retries;
	int result;
	struct scsi_lun *lunp, *lun_data;
	uint8_t *data;
	struct scsi_sense_hdr sshdr;
	struct scsi_device *sdev;
	int ret = 0;

	/*
	 * Only support SCSI-3 and up devices if BLIST_NOREPORTLUN is not set.
	 * Also allow SCSI-2 if BLIST_REPORTLUN2 is set and host adapter does
	 * support more than 8 LUNs.
	 */
	if (bflags & BLIST_NOREPORTLUN)
		return 1;
	if (starget->scsi_level < SCSI_2 &&
	    starget->scsi_level != SCSI_UNKNOWN)
		return 1;
	if (starget->scsi_level < SCSI_3 &&
	    (!(bflags & BLIST_REPORTLUN2) || shost->max_lun <= 8))
		return 1;
	if (bflags & BLIST_NOLUN)
		return 0;

	if (!(sdev = scsi_device_lookup_by_target(shost, starget, 0))) {
		printf("Not found sdev\n");
		sdev = scsi_alloc_sdev(shost, starget, 0, NULL);
		if (!sdev)
			return 0;
	}
	printf("report sdev address is %X\n", sdev);
	printf("sdev->lun is %d\n", sdev->lun);

	sprintf(devname, "host %d channel %d id %d",
		shost->host_no, sdev->channel, sdev->id);	

	printf("devname is %s\n", devname);
	/*
	 * Allocate enough to hold the header (the same size as one scsi_lun)
	 * plus the max number of luns we are requesting.
	 *
	 * Reallocating and trying again (with the exact amount we need)
	 * would be nice, but then we need to somehow limit the size
	 * allocated based on the available memory and the limits of
	 * kmalloc - we don't want a kmalloc() failure of a huge value to
	 * prevent us from finding any LUNs on this target.
	 */
	length = (max_scsi_report_luns + 1) * sizeof(struct scsi_lun);
	lun_data = malloc(length);
	if (!lun_data) {
		printf("%s alloc buffer wrong!\n", __FUNCTION__);
		goto out;
	}

	scsi_cmd[0] = REPORT_LUNS;

	/*
	 * bytes 1 - 5: reserved, set to zero.
	 */
	memset(&scsi_cmd[1], 0, 5);

	/*
	 * bytes 6 - 9: length of the command.
	 */
	scsi_cmd[6] = (unsigned char) (length >> 24) & 0xff;
	scsi_cmd[7] = (unsigned char) (length >> 16) & 0xff;
	scsi_cmd[8] = (unsigned char) (length >> 8) & 0xff;
	scsi_cmd[9] = (unsigned char) length & 0xff;

	scsi_cmd[10] = 0;	/* reserved */
	scsi_cmd[11] = 0;	/* control */

	/*
	 * We can get a UNIT ATTENTION, for example a power on/reset, so
	 * retry a few times (like sd.c does for TEST UNIT READY).
	 * Experience shows some combinations of adapter/devices get at
	 * least two power on/resets.
	 *
	 * Illegal requests (for devices that do not support REPORT LUNS)
	 * should come through as a check condition, and will not generate
	 * a retry.
	 */
	for (retries = 0; retries < 3; retries++) {
		printf("scsi scan: Sending REPORT LUNS to %s (try %d)\n", devname, retries);

		result = scsi_execute_req(shost, sdev, scsi_cmd, DMA_FROM_DEVICE,
					  lun_data, length, &sshdr,
					  SCSI_TIMEOUT + 4 * HZ, 3, 0);

		printf("scsi scan: REPORT LUNS %s (try %d) result 0x%x\n", result ?  "failed" : "successful", retries, result);
		if (result == 0)
			break;
		else if (scsi_sense_valid(&sshdr)) {
			if (sshdr.sense_key != UNIT_ATTENTION)
				break;
		}
	}
	printf("result is %d\n", result);

	if (result) {
		/*
		 * The device probably does not support a REPORT LUN command
		 */
		ret = 1;
		goto out_err;
	}

	/*
	 * Get the length from the first four bytes of lun_data.
	 */
	data = (uint8_t *) lun_data->scsi_lun;
	length = ((data[0] << 24) | (data[1] << 16) |
		  (data[2] << 8) | (data[3] << 0));

	num_luns = (length / sizeof(struct scsi_lun));
	if (num_luns > max_scsi_report_luns) {
		printf("scsi: On %s only %d (max_scsi_report_luns) of %d luns reported, try increasing max_scsi_report_luns.\n", devname,
		       max_scsi_report_luns, num_luns);
		num_luns = max_scsi_report_luns;
	}


	/*
	 * Scan the luns in lun_data. The entry at offset 0 is really
	 * the header, so start at 1 and go up to and including num_luns.
	 */
	for (lunp = &lun_data[1]; lunp <= &lun_data[num_luns]; lunp++) {
		lun = scsilun_to_int(lunp);

		/*
		 * Check if the unused part of lunp is non-zero, and so
		 * does not fit in lun.
		 */
		if (memcmp(&lunp->scsi_lun[sizeof(lun)], "\0\0\0\0", 4)) {
			int i;

			/*
			 * Output an error displaying the LUN in byte order,
			 * this differs from what linux would print for the
			 * integer LUN value.
			 */
			printf("scsi: %s lun 0x", devname);
			data = (char *)lunp->scsi_lun;
			for (i = 0; i < sizeof(struct scsi_lun); i++)
				printf("%02x", data[i]);
			printf(" has a LUN larger than currently supported.\n");
		} else if (lun > sdev->host->max_lun) {
			printf("scsi: %s lun%d has a LUN larger than allowed by the host adapter\n",
			       devname, lun);
		} else {
			int res;

			res = scsi_probe_and_add_lun(shost, starget,
				lun, NULL, NULL, rescan, NULL);
			if (res == SCSI_SCAN_NO_RESPONSE) {
				/*
				 * Got some results, but now none, abort.
				 */
				printf("Unexpected response from lun %d while scanning, scan aborted\n", lun);
				break;
			}
		}
	}

 out_err:
	free(lun_data);
 out:
	if (sdev->sdev_state == SDEV_CREATED)
		/*
		 * the sdev we used didn't appear in the report luns scan
		 */
		scsi_destroy_sdev(sdev);
	printf("scsi_report_lun_scan ret is %d\n", ret);
	return ret;
}


static void __scsi_scan_target(struct Scsi_Host *shost, unsigned int channel,
		unsigned int id, unsigned int lun, int rescan)
{
	printf("__scsi_scan_target\n");
	int bflags = 0;
	int res;
	struct scsi_target *starget;

	if (shost->this_id == id)
		/*
		 * Don't scan the host adapter
		 */
		return;

	starget = scsi_alloc_target(shost, channel, id);
	if (!starget)
		return;

	if (lun != SCAN_WILD_CARD) {
		/*
		 * Scan for a specific host/chan/id/lun.
		 */
		scsi_probe_and_add_lun(shost, starget, lun, NULL, NULL, rescan, NULL);
		return ;
	}

	/*
	 * Scan LUN 0, if there is some response, scan further. Ideally, we
	 * would not configure LUN 0 until all LUNs are scanned.
	 */
	res = scsi_probe_and_add_lun(shost, starget, 0, &bflags, NULL, rescan, NULL);
	if (res == SCSI_SCAN_LUN_PRESENT || res == SCSI_SCAN_TARGET_PRESENT) {
		if (scsi_report_lun_scan(shost, starget, bflags, rescan) != 0)
		{
			/*
			 * The REPORT LUN did not scan the target,
			 * do a sequential scan.
			 */
			printf("scsi_sequential_lun_scan\n");
			scsi_sequential_lun_scan(shost, starget, bflags,
						 starget->scsi_level, rescan);
		}
	}
}

static void scsi_scan_channel(struct Scsi_Host *shost, unsigned int channel,
			      unsigned int id, unsigned int lun, int rescan)
{
	printf("scsi_scan_channel\n");
	uint32_t order_id;

	if (id == SCAN_WILD_CARD)
		for (id = 0; id < shost->max_id; ++id) {
			/*
			 * XXX adapter drivers when possible (FCP, iSCSI)
			 * could modify max_id to match the current max,
			 * not the absolute max.
			 *
			 * XXX add a shost id iterator, so for example,
			 * the FC ID can be the same as a target id
			 * without a huge overhead of sparse id's.
			 */
			if (shost->reverse_ordering)
				/*
				 * Scan from high to low id.
				 */
				order_id = shost->max_id - id - 1;
			else
				order_id = id;
			//__scsi_scan_target(&shost->shost_gendev, channel,
			//		order_id, lun, rescan);
			__scsi_scan_target(shost, channel,
					order_id, lun, rescan);

		}
	else
		//__scsi_scan_target(&shost->shost_gendev, channel,
		//		id, lun, rescan);
		__scsi_scan_target(shost, channel,
					order_id, lun, rescan);

}

int scsi_scan_host_selected(struct Scsi_Host *shost, unsigned int channel,
			    unsigned int id, unsigned int lun, int rescan)
{
	printf("channel:%u, id:%u, lun:%u\n", channel, id, lun);

	if (((channel != SCAN_WILD_CARD) && (channel > shost->max_channel)) ||
	    ((id != SCAN_WILD_CARD) && (id >= shost->max_id)) ||
	    ((lun != SCAN_WILD_CARD) && (lun > shost->max_lun)))
		return -1;

		if (channel == SCAN_WILD_CARD)
			for (channel = 0; channel <= shost->max_channel;
			     channel++)
				scsi_scan_channel(shost, channel, id, lun,
						  rescan);
		else
			scsi_scan_channel(shost, channel, id, lun, rescan);

	return 0;
}


static void do_scsi_scan_host(struct Scsi_Host *shost)
{
		printf("scsi_scan_host_selected\n");
		scsi_scan_host_selected(shost, SCAN_WILD_CARD, SCAN_WILD_CARD,
				SCAN_WILD_CARD, 0);
}


/**
 * scsi_scan_host - scan the given adapter
 * @shost:	adapter to scan
 **/
void scsi_scan_host(struct Scsi_Host *shost)
{
	do_scsi_scan_host(shost);
}


