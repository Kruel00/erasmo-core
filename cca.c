/*
void init_erasing_device(erasing_device_t *const device){

    device->system_path[0] = '\0';
    device->device_type = '\0';
    device->serial_no = '\0';
}*/

/*
typedef struct erasing_device_s{
    char system_path[512];
    int  device_type;
    long long int serial_no; 
}erasing_device_t;*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sg_lib.h"
#include "sg_cmds.h"
#include "sg_pt.h"

#define SG_PATH_SIZE 512
#define ME "Quantum Erasmo:"

void usage(){
    printf("Usage: erasmo  </dev/device> <Device type> <Device serial>\n");
}

typedef enum storage_device_type {

	INTERNAL_SG_DEVICE,
	EXTERNAL_SG_DEVICE,
	NVME_DEVICE,
	INTERNAL_MMC_DEVICE,
	EXTERNAL_MMC_DEVICE,
	UNKNOWN_DEVICE

} StorageDeviceType;

int main(int argc, char *argv[]){

    int sg_fd, k;
    char inf[SG_PATH_SIZE];
    int verbose = 0;
    int do16 = 0;
    int dev_t;
    char serial_num[512];

    //args    
    strcpy(inf,argv[1]);
    dev_t = atoi(argv[2]);
    //strcpy(serial_num,argv[3]);

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


    printf("Erasing device %s...\n",inf);
    
    //open device.
    printf("\n");    
    if ((sg_fd = sg_cmds_open_device(inf, (do16 ? 0 /* rw */ : 1), verbose)) < 0)
    {
        fprintf(stderr, ME " Device %s dont exist\n%s\n", inf, safe_strerror(-sg_fd));
        return EXIT_FAILURE;
    }

    //erase device

return EXIT_SUCCESS;
}

void init_erasing_device(erasing_device_t *const device){

    device->system_path[0] = '\0';
    device->device_type = '\0';
    device->serial_no = '\0';
}