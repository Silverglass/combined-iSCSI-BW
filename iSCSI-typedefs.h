#ifndef __ISCSI_TYPEDEFS_H__
#define __ISCSI_TYPEDEFS_H__

#include "cvmx.h"
#include "cvmx-spinlock.h"

#define CONTEXT_TYPE_ISCSI_SYSTEM 20

#define ISCSI_GRP       12
#define ISCSI_TAG_BASE  0x00010000
//Renjs
#define MAX_LUN_NUMBER 5
typedef struct
{
        uint64_t lun_num;         /* ¾íÊ^? */
        uint64_t sector_size;      /* ÉÇ´ó*/
        uint64_t sector_num[MAX_LUN_NUMBER];  /* ÿ¸öÐÈø^? */
}iSCSI_DiskInfo;
typedef struct
{
        uint64_t initialize_status; 
        uint8_t data_pool;
        iSCSI_DiskInfo* disk_info;
}iSCSI_Init_Result;


enum iscsi_unused_Code
{
	iscsi_Initializae = 64,
	iscsi_Inquiry_asyn=66,//（暂时不提供该接口）
	iscsi_Read_asyn=68,
	iscsi_Write_asyn=70
};


enum iscsi_context_state
{
	iSCSI_START_CONNECT = 100,
	iSCSI_SEND_LOGIN_PDU = 101,
	iSCSI_SEND_LOGIN_CMD = 102,
	iSCSI_RUN = 103
};


typedef struct data_list
{
	uint64_t data_ptr; //fpa buffer的物理地址
	uint8_t data_pool; //fpa buffer来自的pool序号
	uint16_t data_len; //fpa buffer中使用的字节数
	uint16_t offset; //fpa buffer起始读写位置相对字节偏移
	uint16_t copied; //相对于offset的字节偏移量, 表示这个buffer已经拷贝的数据长度
	struct data_list * next; //下一块数据物理地址指针
}	data_list_t;


typedef struct
{
	uint16_t cmd_type; //命令，填写iscsi_unused_Code
	uint64_t context; //上层应用提供标示命令的字段
	uint8_t group; //上层应用提供的数据返回到的group
	uint8_t lun; //读取的磁盘分区序号
	uint64_t start_sector; //起始读写扇区号
	uint64_t byte_size; //读取的字节数量，读写范围
	uint64_t result; //执行结果
}	cmd_info;

typedef struct
{
	data_list_t * data_head; //存储数据的链表，存储read的结果和write的数据，SCSI/iSCSI子系统使用的fpa buffer均由上层应用提供，SCSI/iSCSI子系统只使用、不申请或释放
	cmd_info  cmd; //描述命令的结构体
}	iSCSI_Params;


typedef struct
{
	uint64_t context_type;
	int socket_fd;
	uint64_t state;	
	uint64_t session; //session的物理地址
	uint64_t conn;	//conn的物理地址
	//uint64_t lock; //存储一个work的物理地址，用于多核之间加锁
	volatile uint64_t syn_among_core; 
	cvmx_spinlock_t lock; //用于多核之间加锁
  volatile uint64_t itt_used; //表示当前itt_queue的使用情况

  //Renjs
  uint64_t write_time;
  uint64_t ip;
  uint64_t lun;
} iSCSI_context;
#endif
