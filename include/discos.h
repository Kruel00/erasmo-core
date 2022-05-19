#include <stdbool.h>
typedef struct mount_point_s {

	char path[512];

} mount_point_t;

typedef struct disco_t {
    int host_no;        /* as in "scsi<n>" where 'n' is one of 0, 1, 2 etc */
    int channel;
    int scsi_id;        /* scsi id of target device */
    int lun;
    int scsi_type;      /* TYPE_... defined in scsi/scsi.h */
    short h_cmd_per_lun;/* host (adapter) maximum commands per lun */
    short d_queue_depth;/* device (or adapter) maximum queue length */
    int unused1;        /* probably find a good use, set 0 for now */
    int unused2;        /* ditto */
} disco_t;

typedef struct partition_s {

	char name[64];
	int postfix;
	char filesystem_type[16];
	char filesystem_uuid[64];
	char label[64];

	unsigned long long int start_sector;
	unsigned long long int total_sectors;
	unsigned long long int sector_size;

	unsigned long long int capacity_bytes;
	unsigned long long int used_bytes;

	mount_point_t *mount_points;
	size_t mount_point_count;

} partition_t;



typedef enum storage_device_type {

	INTERNAL_SG_DEVICE,
	EXTERNAL_SG_DEVICE,
	NVME_DEVICE,
	INTERNAL_MMC_DEVICE,
	EXTERNAL_MMC_DEVICE,
	UNKNOWN_DEVICE

} StorageDeviceType;

typedef struct storage_device_s{
    char sys_path[512];
    char filename[128];
    char name[32];
    char bus[32];
    char partition_table_type[32];
	char partition_table_uuid[64];
    int  open_num;
    int  cmd_len;
	char usb_driver[32];
	char type_attribute[32];
    unsigned long int sectors;
    unsigned int block_size;
    char type[32];
    char brand[64];
    char model[64];
    char serial_number[256];

    size_t partition_count;
    partition_t *partitions;


}storage_device_t;



typedef struct storage_device_list_s
{
    storage_device_t *device;
    int count;
}storage_device_list_t;


typedef struct erasing_device_s{
	int open_res;
    char system_path[512];
    int  device_type;
    char serial_no[512]; 
	int block_size;
	unsigned long long int total_sectors;
	char capacity[32];
    bool erased;
}erasing_device_t;


