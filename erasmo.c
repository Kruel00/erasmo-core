/*########################################################
    Javier Castorena <javier.castorena@reconext.com>
    gcc -o erasmo erasmo.c sg_cmds.c sg_pt_linux.c sg_lib.c  sg_io_linux.c -I./include
##########################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sg_lib.h"
#include "sg_cmds.h"
#include "sg_pt.h"
#include "discos.h"

#define SG_PATH_SIZE 512
#define ME "Quantum Erasmo:"
#define NVME_DEVICE_TYPE "nvme"
#define MX_ALLOC_LEN (0xc000 + 0x80)
#define SAFE_STD_INQ_RESP_LEN 36
#define RCAP16_REPLY_LEN 32
#define RCAP_REPLY_LEN 8


int sg_fd,k;
int pmi = 0;
int lba = 0;
unsigned long long llba = 0;
unsigned long long u, llast_blk_addr;
unsigned int last_blk_addr, block_size;
static int verbose = 0;
static unsigned char rsp_buff[MX_ALLOC_LEN + 1];
unsigned char resp_buff[RCAP16_REPLY_LEN];
static char xtra_buff[MX_ALLOC_LEN + 1];
int res2, len, act_len, pqual, peri_type, ansi_version, ret, j, support_num,num,reserved_cmddt;

void init_erasing_device(erasing_device_t *const device);
void get_block_size(erasing_device_t *const device);
void set_device_capacity(erasing_device_t *const device);

void usage(){
    printf("Usage: erasmo  </dev/device> <Device type> <Device serial>\n");
}

int main(int argc, char *argv[]){

    char inf[SG_PATH_SIZE];
    int verbose = 0;
    int do16 = 0;
    int dev_t;
    char serial_num[512];

    //args    
    strcpy(inf,argv[1]);
    dev_t = atoi(argv[2]);
    strcpy(serial_num,argv[3]);

    if(argc != 4 ){
        usage();
        return EXIT_FAILURE;
    }
    else if(*inf != '/'){
        usage();
        return EXIT_FAILURE;
    }
    else if(dev_t > 5 | dev_t < 1){
        usage(); 
        printf("Device type dont exist\n"
        "1.- Internal SATA Device\n"
	    "2.- External SATA Device\n"
	    "3.- nvme Device\n"
	    "4.- internal MMC Device\n"
	    "5.- External MMC Device\n"
	    "6.- Unknown Device\n");
        return EXIT_FAILURE;
    }

    printf("Erasing device %s...\nDevice type: %i\nSerial number: %s",inf,dev_t,serial_num);
    
    //open device.
    printf("\n");    
    if ((sg_fd = sg_cmds_open_device(inf, (do16 ? 0 /* rw */ : 1), verbose)) < 0)
    {
        fprintf(stderr, ME " Device %s dont exist\n%s\n", inf, safe_strerror(-sg_fd));
        return EXIT_FAILURE;
    }

    //get device data
    erasing_device_t device;
    init_erasing_device(&device);

    strcpy(device.system_path,inf);
    device.device_type = dev_t;
    strcpy(device.serial_no, serial_num);
    device.open_res = sg_fd;

    get_block_size(&device);
    set_device_capacity(&device);

    printf("data: %i\n",device.block_size);

    //erase device


return EXIT_SUCCESS;
}

void init_erasing_device(erasing_device_t *const device){
    device->system_path[0] = '\0';
    device->device_type = '\0';
    device->serial_no[0] = '\0';
    device->block_size = '\0';
    device->capacity[0] = '\0';
}

void get_block_size(erasing_device_t *const device){
    int res;
    res = sg_ll_readcap_10(sg_fd, pmi, lba, resp_buff, RCAP_REPLY_LEN, 0, verbose);

    if (0 == res)
    {
        last_blk_addr = ((resp_buff[0] << 24) | (resp_buff[1] << 16) |
                         (resp_buff[2] << 8) | resp_buff[3]);
    }

    if (0xffffffff != last_blk_addr)
    {
        block_size = ((resp_buff[4] << 24) | (resp_buff[5] << 16) |
                      (resp_buff[6] << 8) | resp_buff[7]);
    }
    else
    {
        sg_cmds_close_device(sg_fd);
        res = sg_ll_readcap_16(sg_fd, pmi, llba, resp_buff, RCAP16_REPLY_LEN, 0, verbose);
        
        if (0 == res)
        {
            for (k = 0, llast_blk_addr = 0; k < 8; ++k)
            {
                llast_blk_addr <<= 8;
                llast_blk_addr |= resp_buff[k];
            }
            block_size = ((resp_buff[8] << 24) | (resp_buff[9] << 16) |
                          (resp_buff[10] << 8) | resp_buff[11]);
        }
    }
    device->block_size = block_size;
    device->total_sectors = last_blk_addr - 1; 
}

void set_device_capacity(erasing_device_t *const device){
    char dev_capacity[32];
    double dev_gb = ((double)(device->total_sectors + 1) * device->block_size) / (double)(1000000000L);
    sprintf(dev_capacity,"%.2f GB",dev_gb);
    strcpy(device->capacity,dev_capacity);
}
