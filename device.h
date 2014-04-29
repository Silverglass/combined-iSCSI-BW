#ifndef __SCSI_DEVICE_H
#define __SCSI_DEVICE_H

#include "cvmx.h"

enum scsi_operation {
        READ = 1,
        WRITE,
        NONE,
};

#define driver_byte(result) (((result) >> 24) & 0xff)


#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

struct list_head {
	struct list_head *next, *prev;
};

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}
static inline void __list_add(struct list_head *new,
                              struct list_head *prev,
                              struct list_head *next)
{
        next->prev = new;
        new->next = next;
        new->prev = prev;
        prev->next = new;
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
        __list_add(new, head->prev, head);
}


/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})


/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_struct within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

static inline void prefetch(const void *x) {;}

/**
 * list_for_each_entry	-	iterate over list of given type
 * @pos:	the type * to use as a loop cursor.
 * @head:	the head for your list.
 * @member:	the name of the list_struct within the struct.
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     prefetch(pos->member.next), &pos->member != (head); 	\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

/* Linux Atomic Ops support */
typedef struct { int counter; } atomic_t;


/*
 * sdev state: If you alter this, you also need to alter scsi_sysfs.c
 * (for the ascii descriptions) and the state model enforcer:
 * scsi_lib:scsi_device_set_state().
 */
enum scsi_device_state {
	SDEV_CREATED = 1,	/* device created but not added to sysfs
				 * Only internal commands allowed (for inq) */
	SDEV_RUNNING,		/* device properly configured
				 * All commands allowed */
	SDEV_CANCEL,		/* beginning to delete device
				 * Only error handler commands allowed */
	SDEV_DEL,		/* device deleted 
				 * no commands allowed */
	SDEV_QUIESCE,		/* Device quiescent.  No block commands
				 * will be accepted, only specials (which
				 * originate in the mid-layer) */
	SDEV_OFFLINE,		/* Device offlined (by error handling or
				 * user request */
	SDEV_BLOCK,		/* Device blocked by scsi lld.  No scsi 
				 * commands from user or midlayer should be issued
				 * to the scsi lld. */
};



enum rq_cmd_type_bits {
	REQ_TYPE_FS		= 1,	/* fs request */
	REQ_TYPE_BLOCK_PC,		/* scsi command */
	REQ_TYPE_SENSE,			/* sense request */
	REQ_TYPE_PM_SUSPEND,		/* suspend request */
	REQ_TYPE_PM_RESUME,		/* resume request */
	REQ_TYPE_PM_SHUTDOWN,		/* shutdown request */
	REQ_TYPE_FLUSH,			/* flush request */
	REQ_TYPE_SPECIAL,		/* driver defined type */
	REQ_TYPE_LINUX_BLOCK,		/* generic block layer message */
	/*
	 * for ATA/ATAPI devices. this really doesn't belong here, ide should
	 * use REQ_TYPE_SPECIAL and use rq->cmd[0] with the range of driver
	 * private REQ_LB opcodes to differentiate what type of request this is
	 */
	REQ_TYPE_ATA_CMD,
	REQ_TYPE_ATA_TASK,
	REQ_TYPE_ATA_TASKFILE,
	REQ_TYPE_ATA_PC,
};



/*
 * This is a slightly modified SCSI sense "descriptor" format header.
 * The addition is to allow the 0x70 and 0x71 response codes. The idea
 * is to place the salient data from either "fixed" or "descriptor" sense
 * format into one structure to ease application processing.
 *
 * The original sense buffer should be kept around for those cases
 * in which more information is required (e.g. the LBA of a MEDIUM ERROR).
 */
struct scsi_sense_hdr {		/* See SPC-3 section 4.5 */
	uint8_t response_code;	/* permit: 0x0, 0x70, 0x71, 0x72, 0x73 */
	uint8_t sense_key;
	uint8_t asc;
	uint8_t ascq;
	uint8_t byte4;
	uint8_t byte5;
	uint8_t byte6;
	uint8_t additional_length;	/* always 0 for fixed sense format */
};

struct scsi_mode_data {
	uint32_t	length;
	uint16_t	block_descriptor_length;
	uint8_t	medium_type;
	uint8_t	device_specific;
	uint8_t	header_length;
	uint8_t	longlba:1;
};

struct scsi_device {
	struct Scsi_Host *host;
	//struct request_queue *request_queue; /*block device request queue, there is no block device, so we comment it*/

	/* the next two are protected by the host->host_lock */
	struct list_head    siblings;   /* list of all devices on this host */
	struct list_head    same_target_siblings; /* just the devices sharing same target id */

	/* this is now protected by the request_queue->queue_lock */
	unsigned int device_busy;	/* commands actually active on
					 * low-level. protected by queue_lock. */
	//spinlock_t list_lock;
	struct list_head cmd_list;	/* queue of in use SCSI Command structures */
	struct list_head starved_entry;
	struct scsi_cmnd *current_cmnd;	/* currently active command */
	unsigned short queue_depth;	/* How deep of a queue we want */
	unsigned short last_queue_full_depth; /* These two are used by */
	unsigned short last_queue_full_count; /* scsi_track_queue_full() */
	unsigned long last_queue_full_time;/* don't let QUEUE_FULLs on the same
					   jiffie count on our counter, they
					   could all be from the same event. */

	unsigned int id, lun, channel;

	unsigned int manufacturer;	/* Manufacturer of device, for using 
					 * vendor-specific cmd's */
	unsigned sector_size;	/* size in bytes */

	void *hostdata;		/* available to low-level driver */
	char type;
	char scsi_level;
	char inq_periph_qual;	/* PQ from INQUIRY data */	
	unsigned char inquiry_len;	/* valid bytes in 'inquiry' */
	unsigned char * inquiry;	/* INQUIRY response data */
	const char * vendor;		/* [back_compat] point into 'inquiry' ... */
	const char * model;		/* ... after scan; point to static string */
	const char * rev;		/* ... "nullnullnullnull" before scan */
	unsigned char current_tag;	/* current tag */
	struct scsi_target      *sdev_target;   /* used only for single_lun */

	unsigned int	sdev_bflags; /* black/white flags as also found in
				 * scsi_devinfo.[hc]. For now used only to
				 * pass settings from slave_alloc to scsi
				 * core. */
	unsigned writeable:1;
	unsigned removable:1;
	unsigned changed:1;	/* Data invalid due to media change */
	unsigned busy:1;	/* Used to prevent races */
	unsigned lockable:1;	/* Able to prevent media removal */
	unsigned locked:1;      /* Media removal disabled */
	unsigned borken:1;	/* Tell the Seagate driver to be 
				 * painfully slow on this device */
	unsigned disconnect:1;	/* can disconnect */
	unsigned soft_reset:1;	/* Uses soft reset option */
	unsigned sdtr:1;	/* Device supports SDTR messages */
	unsigned wdtr:1;	/* Device supports WDTR messages */
	unsigned ppr:1;		/* Device supports PPR messages */
	unsigned tagged_supported:1;	/* Supports SCSI-II tagged queuing */
	unsigned simple_tags:1;	/* simple queue tag messages are enabled */
	unsigned ordered_tags:1;/* ordered queue tag messages are enabled */
	unsigned single_lun:1;	/* Indicates we should only allow I/O to
				 * one of the luns for the device at a 
				 * time. */
	unsigned was_reset:1;	/* There was a bus reset on the bus for 
				 * this device */
	unsigned expecting_cc_ua:1; /* Expecting a CHECK_CONDITION/UNIT_ATTN
				     * because we did a bus reset. */
	unsigned use_10_for_rw:1; /* first try 10-byte read / write */
	unsigned use_10_for_ms:1; /* first try 10-byte mode sense/select */
	unsigned skip_ms_page_8:1;	/* do not use MODE SENSE page 0x08 */
	unsigned skip_ms_page_3f:1;	/* do not use MODE SENSE page 0x3f */
	unsigned use_192_bytes_for_3f:1; /* ask for 192 bytes from page 0x3f */
	unsigned no_start_on_add:1;	/* do not issue start on add */
	unsigned allow_restart:1; /* issue START_UNIT in error handler */
	unsigned no_uld_attach:1; /* disable connecting to upper level drivers */
	unsigned select_no_atn:1;
	unsigned fix_capacity:1;	/* READ_CAPACITY is too high by 1 */
	unsigned guess_capacity:1;	/* READ_CAPACITY might be too high by 1 */
	unsigned retry_hwerror:1;	/* Retry HARDWARE_ERROR */

	unsigned int device_blocked;	/* Device returned QUEUE_FULL. */

	unsigned int max_device_blocked; /* what device_blocked counts down from  */
#define SCSI_DEFAULT_DEVICE_BLOCKED	3

	atomic_t iorequest_cnt;
	atomic_t iodone_cnt;
	atomic_t ioerr_cnt;

	int timeout;

	//struct device		sdev_gendev;
	//struct class_device	sdev_classdev;

	//struct execute_work	ew; /* used to get process context on put */

	enum scsi_device_state sdev_state;
	unsigned long		sdev_data[0];
} __attribute__((aligned(sizeof(unsigned long))));

typedef uint64_t sector_t;

typedef struct pm_message {
	int event;
} pm_message_t;


struct scsi_host_template {
	//struct module *module;
	const char *name;

	int (* detect)(struct scsi_host_template *);

	int (* release)(struct Scsi_Host *);

	const char *(* info)(struct Scsi_Host *);

	int (* ioctl)(struct scsi_device *dev, int cmd, void *arg);


#ifdef CONFIG_COMPAT
	int (* compat_ioctl)(struct scsi_device *dev, int cmd, void *arg);
#endif

	int (* queuecommand)(struct scsi_cmnd *,
			     void (*done)(struct scsi_cmnd *));

	int (* transfer_response)(struct scsi_cmnd *,
				  void (*done)(struct scsi_cmnd *));
	int (* transfer_data)(struct scsi_cmnd *,
			      void (*done)(struct scsi_cmnd *));

	int (* tsk_mgmt_response)(uint64_t mid, int result);

	int (* eh_abort_handler)(struct scsi_cmnd *);
	int (* eh_device_reset_handler)(struct scsi_cmnd *);
	int (* eh_bus_reset_handler)(struct scsi_cmnd *);
	int (* eh_host_reset_handler)(struct scsi_cmnd *);

	int (* slave_alloc)(struct scsi_device *);

	int (* slave_configure)(struct scsi_device *);

	void (* slave_destroy)(struct scsi_device *);

	int (* target_alloc)(struct scsi_target *);

	void (* target_destroy)(struct scsi_target *);

	int (* scan_finished)(struct Scsi_Host *, unsigned long);

	void (* scan_start)(struct Scsi_Host *);

	int (* change_queue_depth)(struct scsi_device *, int);

	int (* change_queue_type)(struct scsi_device *, int);

	int (*proc_info)(struct Scsi_Host *, char *, char **, off_t, int, int);

	int (*resume)(struct scsi_device *);
	int (*suspend)(struct scsi_device *, pm_message_t state);

	char *proc_name;

	//struct proc_dir_entry *proc_dir;

	int can_queue;

	int this_id;

	unsigned short sg_tablesize;

	unsigned short max_sectors;

	unsigned long dma_boundary;

#define SCSI_DEFAULT_MAX_SECTORS	1024

	short cmd_per_lun;

	unsigned char present;

	unsigned unchecked_isa_dma:1;

	unsigned use_clustering:1;

	unsigned emulated:1;

	unsigned skip_settle_delay:1;

	unsigned ordered_tag:1;

	unsigned int max_host_blocked;

#define SCSI_DEFAULT_HOST_BLOCKED	7

	//struct class_device_attribute **shost_attrs;

	//struct device_attribute **sdev_attrs;

	/*
	 * List of hosts per template.
	 *
	 * This is only for use by scsi_module.c for legacy templates.
	 * For these access to it is synchronized implicitly by
	 * module_init/module_exit.
	 */
	struct list_head legacy_hosts;
};





/*
 * shost state: If you alter this, you also need to alter scsi_sysfs.c
 * (for the ascii descriptions) and the state model enforcer:
 * scsi_host_set_state()
 */
enum scsi_host_state {
	SHOST_CREATED = 1,
	SHOST_RUNNING,
	SHOST_CANCEL,
	SHOST_DEL,
	SHOST_RECOVERY,
	SHOST_CANCEL_RECOVERY,
	SHOST_DEL_RECOVERY,
};





struct Scsi_Host {
	struct list_head	__devices;
	struct list_head	__targets;
	
	//struct scsi_host_cmd_pool *cmd_pool;
	//spinlock_t		free_list_lock;
	struct list_head	free_list; /* backup store of cmd structs */
	struct list_head	starved_list;

	//spinlock_t		default_lock;
	//spinlock_t		*host_lock;

	//struct mutex		scan_mutex;/* serialize scanning activity */

	struct list_head	eh_cmd_q;
	//struct task_struct    * ehandler;  /* Error recovery thread. */
	//struct completion     * eh_action; /* Wait for specific actions on the host. */
	//wait_queue_head_t       host_wait;
	struct scsi_host_template *hostt;
	//struct scsi_transport_template *transportt;

	/*
	 * area to keep a shared tag map (if needed, will be
	 * NULL if not)
	 */
	//struct blk_queue_tag	*bqt;

	/*
	 * The following two fields are protected with host_lock;
	 * however, eh routines can safely access during eh processing
	 * without acquiring the lock.
	 */
	unsigned int host_busy;		   /* commands actually active on low-level */
	unsigned int host_failed;	   /* commands that failed. */
	unsigned int host_eh_scheduled;    /* EH scheduled without command */
    
	unsigned short host_no;  /* Used for IOCTL_GET_IDLUN, /proc/scsi et al. */
	int resetting; /* if set, it means that last_reset is a valid value */
	unsigned long last_reset;

	/*
	 * These three parameters can be used to allow for wide scsi,
	 * and for host adapters that support multiple busses
	 * The first two should be set to 1 more than the actual max id
	 * or lun (i.e. 8 for normal systems).
	 */
	unsigned int max_id;
	unsigned int max_lun;
	unsigned int max_channel;

	/*
	 * This is a unique identifier that must be assigned so that we
	 * have some way of identifying each detected host adapter properly
	 * and uniquely.  For hosts that do not support more than one card
	 * in the system at one time, this does not need to be set.  It is
	 * initialized to 0 in scsi_register.
	 */
	unsigned int unique_id;

	/*
	 * The maximum length of SCSI commands that this host can accept.
	 * Probably 12 for most host adapters, but could be 16 for others.
	 * For drivers that don't set this field, a value of 12 is
	 * assumed.  I am leaving this as a number rather than a bit
	 * because you never know what subsequent SCSI standards might do
	 * (i.e. could there be a 20 byte or a 24-byte command a few years
	 * down the road?).  
	 */
	unsigned char max_cmd_len;

	int this_id;
	int can_queue;
	short cmd_per_lun;
	short unsigned int sg_tablesize;
	short unsigned int max_sectors;
	unsigned long dma_boundary;
	/* 
	 * Used to assign serial numbers to the cmds.
	 * Protected by the host lock.
	 */
	unsigned long cmd_serial_number, cmd_pid; 
	
	unsigned unchecked_isa_dma:1;
	unsigned use_clustering:1;
	unsigned use_blk_tcq:1;

	/*
	 * Host has requested that no further requests come through for the
	 * time being.
	 */
	unsigned host_self_blocked:1;
    
	/*
	 * Host uses correct SCSI ordering not PC ordering. The bit is
	 * set for the minority of drivers whose authors actually read
	 * the spec ;)
	 */
	unsigned reverse_ordering:1;

	/*
	 * ordered write support
	 */
	unsigned ordered_tag:1;

	/* task mgmt function in progress */
	unsigned tmf_in_progress:1;

	/* Asynchronous scan in progress */
	unsigned async_scan:1;

	/*
	 * Optional work queue to be utilized by the transport
	 */
	//char work_q_name[KOBJ_NAME_LEN];
	//struct workqueue_struct *work_q;

	/*
	 * Host has rejected a command because it was busy.
	 */
	unsigned int host_blocked;

	/*
	 * Value host_blocked counts down from
	 */
	unsigned int max_host_blocked;

	/*
	 * q used for scsi_tgt msgs, async events or any other requests that
	 * need to be processed in userspace
	 */
	//struct request_queue *uspace_req_q;

	/* legacy crap */
	unsigned long base;
	unsigned long io_port;
	unsigned char n_io_port;
	unsigned char dma_channel;
	unsigned int  irq;
	

	enum scsi_host_state shost_state;

	/* ldm bits */
	//struct device		shost_gendev;
	//struct class_device	shost_classdev;

	/*
	 * List of hosts per template.
	 *
	 * This is only for use by scsi_module.c for legacy templates.
	 * For these access to it is synchronized implicitly by
	 * module_init/module_exit.
	 */
	struct list_head sht_legacy_list;

	/*
	 * Points to the transport data (if any) which is allocated
	 * separately
	 */
	void *shost_data;

	/*
	 * We should ensure that this is aligned, both for better performance
	 * and also because some compilers (m68k) don't automatically force
	 * alignment to a long boundary.
	 */
	unsigned long hostdata[0]  /* Used for storage of host specific stuff */
		__attribute__ ((aligned (sizeof(unsigned long))));
};



enum scsi_target_state {
	STARGET_RUNNING = 1,
	STARGET_DEL,
};


/*
 * scsi_target: representation of a scsi target, for now, this is only
 * used for single_lun devices. If no one has active IO to the target,
 * starget_sdev_user is NULL, else it points to the active sdev.
 */
struct scsi_target {
	struct scsi_device	*starget_sdev_user;
	struct list_head	siblings;
	struct list_head	devices;
	//struct device		dev;
	unsigned int		reap_ref; /* protected by the host lock */
	unsigned int		channel;
	unsigned int		id; /* target id ... replace
				     * scsi_device.id eventually */
	unsigned int		create:1; /* signal that it needs to be added */
	unsigned int		pdt_1f_for_no_lun;	/* PDT = 0x1f */
						/* means no lun present */

	char			scsi_level;
	//struct execute_work	ew;
	enum scsi_target_state	state;
	void 			*hostdata; /* available to low-level driver */
	unsigned long		starget_data[0]; /* for the transport */
	/* starget_data must be the last element!!!! */
} __attribute__((aligned(sizeof(unsigned long))));




/* These definitions mirror those in pci.h, so they can be used
 * interchangeably with their PCI_ counterparts */
enum dma_data_direction {
	DMA_BIDIRECTIONAL = 0,
	DMA_TO_DEVICE = 1,
	DMA_FROM_DEVICE = 2,
	DMA_NONE = 3,
};


struct scsi_cmnd {
	struct scsi_device *device;
	struct list_head list;  /* scsi_cmnd participates in queue lists */
	struct list_head eh_entry; /* entry for the host eh_cmd_q */
	int eh_eflags;		/* Used by error handlr */
	void (*done) (struct scsi_cmnd *);	/* Mid-level done function */

	/*
	 * A SCSI Command is assigned a nonzero serial_number before passed
	 * to the driver's queue command function.  The serial_number is
	 * cleared when scsi_done is entered indicating that the command
	 * has been completed.  It currently doesn't have much use other
	 * than printk's.  Some lldd's use this number for other purposes.
	 * It's almost certain that such usages are either incorrect or
	 * meaningless.  Please kill all usages other than printk's.  Also,
	 * as this number is always identical to ->pid, please convert
	 * printk's to use ->pid, so that we can kill this field.
	 */
	unsigned long serial_number;
	/*
	 * This is set to jiffies as it was when the command was first
	 * allocated.  It is used to time how long the command has
	 * been outstanding
	 */
	unsigned long jiffies_at_alloc;

	int retries;
	int allowed;
	int timeout_per_command;

	unsigned char cmd_len;
	enum dma_data_direction sc_data_direction;

	/* These elements define the operation we are about to perform */
#define MAX_COMMAND_SIZE	16
	unsigned char cmnd[MAX_COMMAND_SIZE];
	unsigned request_bufflen;	/* Actual request size */

	void *request_buffer;		/* Actual requested buffer */
	void *request_buffer_ptr;		/* Actual requested buffer */

	/* These elements define the operation we ultimately want to perform */
	unsigned short use_sg;	/* Number of pieces of scatter-gather */
	unsigned short sglist_len;	/* size of malloc'd scatter-gather list */

	/* offset in cmd we are at (for multi-transfer tgt cmds) */
	unsigned offset;

	unsigned underflow;	/* Return error if less than
				   this amount is transferred */

	unsigned transfersize;	/* How much we are guaranteed to
				   transfer with each SCSI transfer
				   (ie, between disconnect / 
				   reconnects.   Probably == sector
				   size */

	int resid;		/* Number of bytes requested to be
				   transferred less actual number
				   transferred (0 if not supported) */


#define SCSI_SENSE_BUFFERSIZE 	96
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
				/* obtained by REQUEST SENSE when
				 * CHECK CONDITION is received on original
				 * command (auto-sense) */

	/* Low-level done function - can be used by low-level driver to point
	 *        to completion function.  Not used by mid/upper level code. */
	void (*scsi_done) (struct scsi_cmnd *);

	/*
	 * The following fields can be written to by the host specific code. 
	 * Everything else should be left alone. 
	 */
	//struct scsi_pointer SCp;	/* Scratchpad used by some host adapters */

	unsigned char *host_scribble;	/* The host adapter is allowed to
					 * call scsi_malloc and get some memory
					 * and hang it here.  The host adapter
					 * is also expected to call scsi_free
					 * to release this memory.  (The memory
					 * obtained by scsi_malloc is guaranteed
					 * to be at an address < 16Mb). */

	int result;		/* Status code from lower level driver */

	unsigned char tag;	/* SCSI-II queued command tag */
	unsigned long pid;	/* Process ID, starts at 0. Unique per host. */


	//add by gxy
	uint64_t app_work;
	uint64_t context;

};


struct Scsi_Host_List {
	int host_num;
	struct Scsi_Host * shost;
        struct list_head list;
};

extern struct Scsi_Host *scsi_host_alloc(struct scsi_host_template *sht, int privsize);
extern int scsi_add_host(struct Scsi_Host *shost);
extern void scsi_scan_host(struct Scsi_Host *shost);
#endif
