/*########################################################
    Javier Castorena <javier.castorena@reconext.com>
    gcc -o erasmo erasmo.c sg_cmds.c sg_pt_linux.c sg_lib.c  sg_io_linux.c -I./include
##########################################################*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <scsi/scsi_ioctl.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <stdint.h>

#include "sg_lib.h"
#include "sg_cmds.h"
#include "sg_io_linux.h"
#include "llseek.h"
#include "sg_pt.h"
#include "discos.h"


#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */
#define MAX_SCSI_CDBSZ 16
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define SG_DD_BYPASS 999        /* failed but coe set */
#define SG_PATH_SIZE 512
#define ME "Quantum Erasmo:"
#define NVME_DEVICE_TYPE "nvme"
#define MX_ALLOC_LEN (0xc000 + 0x80)
#define SAFE_STD_INQ_RESP_LEN 36
#define RCAP16_REPLY_LEN 32
#define RCAP_REPLY_LEN 8
#define DEF_SCSI_CDBSZ 10



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
static int cmd_timeout = DEF_TIMEOUT;   /* in milliseconds */
static bool do_verify = false;          /* when false: do copy */
static uint32_t glob_pack_id = 0;       /* pre-increment */
static int recovered_errs = 0;
static int unrecovered_errs = 0;
static int miscompare_errs = 0;
static struct flags_t iflag;
static struct flags_t oflag;
static int blk_sz = 512;
int dio = 0;


struct flags_t {
    bool append;
    bool dio;
    bool direct;
    bool dpo;
    bool dsync;
    bool excl;
    bool flock;
    bool ff;
    bool fua;
    bool nocreat;
    bool random;
    bool sgio;
    bool sparse;
    bool zero;
    int cdbsz;
    int cdl;
    int coe;
    int nocache;
    int pdt;
    int retries;
};

void init_erasing_device(erasing_device_t *const device);
void get_block_size(erasing_device_t *const device);
void set_device_capacity(erasing_device_t *const device);
static int sg_build_scsi_cdb(unsigned char *cdbp, int cdb_sz, unsigned int blocks, long long start_block, int write_true, int fua, int dpo);
static int sg_write(int sg_fd, unsigned char *buff, int blocks, long long to_block, int bs, int cdbsz, int fua, int dpo, int *diop);
int erase_device(erasing_device_t *const device);


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

    if(erase_device(&device))
        printf("\n\t Todo OK\n");

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




/* 0 -> successful, -1 -> unrecoverable error, -2 -> recoverable (ENOMEM),
   -3 -> try again (media changed unit attention) */
static int sg_write(int sg_fd, unsigned char *buff, int blocks, long long to_block, int bs, int cdbsz, int fua, int dpo, int *diop){

    unsigned char wrCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res, k, info_valid;
    unsigned long long io_addr = 0;

    if (sg_build_scsi_cdb(wrCmd, cdbsz, blocks, to_block, 1, fua, dpo))
    {
        fprintf(stderr, ME " bad wr cdb build, to_block=%lld, blocks=%d\n", to_block, blocks);
        return -1;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)to_block;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    if (verbose > 2)
    {
        fprintf(stderr, "    write cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", wrCmd[k]);
        fprintf(stderr, "\n");
    }
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0)
    {
        if (ENOMEM == errno)
            return -2;
        perror("writing (SG_IO) on sg device, error");
        return -1;
    }

    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    switch (sg_err_category3(&io_hdr))
    {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        ++recovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr, &io_addr);

        if (info_valid)
        {
            fprintf(stderr, "    lba of last recovered error in this WRITE=0x%llx\n", io_addr);
            if (verbose > 1)
                sg_chk_n_print3("writing", &io_hdr, 1);
        }
        else
        {
            fprintf(stderr, "Recovered error: [no info] writing to "
                            "block=0x%llx, num=%d\n",
                    to_block, blocks);
            sg_chk_n_print3("writing", &io_hdr, verbose > 1);
        }
        break;
    case SG_LIB_CAT_MEDIA_CHANGED:
        if (verbose > 1)
            sg_chk_n_print3("writing", &io_hdr, 1);
        return -3;
    default:
        sg_chk_n_print3("writing", &io_hdr, verbose > 1);
        if (oflag.coe)
        {
            fprintf(stderr, ">> ignored errors for out blk=%lld for "
                            "%d bytes\n",
                    to_block, bs * blocks);
            return 0; /* fudge success */
        }
        else
            return -1;
    }
    if (diop && *diop &&
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0; /* flag that dio not done (completely) */
    return 0;
}

static int sg_build_scsi_cdb(unsigned char *cdbp, int cdb_sz,
                             unsigned int blocks, long long start_block,
                             int write_true, int fua, int dpo)
{
    int rd_opcode[] = {0x8, 0x28, 0xa8, 0x88};
    int wr_opcode[] = {0xa, 0x2a, 0xaa, 0x8a};
    int sz_ind;

    memset(cdbp, 0, cdb_sz);
    if (dpo)
        cdbp[1] |= 0x10;
    if (fua)
        cdbp[1] |= 0x8;
    switch (cdb_sz)
    {
    case 6:
        sz_ind = 0;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] : rd_opcode[sz_ind]);
        cdbp[1] = (unsigned char)((start_block >> 16) & 0x1f);
        cdbp[2] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[3] = (unsigned char)(start_block & 0xff);
        cdbp[4] = (256 == blocks) ? 0 : (unsigned char)blocks;
        if (blocks > 256)
        {
            fprintf(stderr, ME "for 6 byte commands, maximum number of "
                               "blocks is 256\n");
            return 1;
        }
        if ((start_block + blocks - 1) & (~0x1fffff))
        {
            fprintf(stderr, ME "for 6 byte commands, can't address blocks"
                               " beyond %d\n",
                    0x1fffff);
            return 1;
        }
        if (dpo || fua)
        {
            fprintf(stderr, ME "for 6 byte commands, neither dpo nor fua"
                               " bits supported\n");
            return 1;
        }
        break;
    case 10:
        sz_ind = 1;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] : rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[8] = (unsigned char)(blocks & 0xff);
        if (blocks & (~0xffff))
        {
            fprintf(stderr, ME "for 10 byte commands, maximum number of "
                               "blocks is %d\n",
                    0xffff);
            return 1;
        }
        break;
    case 12:
        sz_ind = 2;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] : rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[5] = (unsigned char)(start_block & 0xff);
        cdbp[6] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[7] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[8] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[9] = (unsigned char)(blocks & 0xff);
        break;
    case 16:
        sz_ind = 3;
        cdbp[0] = (unsigned char)(write_true ? wr_opcode[sz_ind] : rd_opcode[sz_ind]);
        cdbp[2] = (unsigned char)((start_block >> 56) & 0xff);
        cdbp[3] = (unsigned char)((start_block >> 48) & 0xff);
        cdbp[4] = (unsigned char)((start_block >> 40) & 0xff);
        cdbp[5] = (unsigned char)((start_block >> 32) & 0xff);
        cdbp[6] = (unsigned char)((start_block >> 24) & 0xff);
        cdbp[7] = (unsigned char)((start_block >> 16) & 0xff);
        cdbp[8] = (unsigned char)((start_block >> 8) & 0xff);
        cdbp[9] = (unsigned char)(start_block & 0xff);
        cdbp[10] = (unsigned char)((blocks >> 24) & 0xff);
        cdbp[11] = (unsigned char)((blocks >> 16) & 0xff);
        cdbp[12] = (unsigned char)((blocks >> 8) & 0xff);
        cdbp[13] = (unsigned char)(blocks & 0xff);
        break;
    default:
        fprintf(stderr, ME "expected cdb size of 6, 10, 12, or 16 but got"
                           " %d\n",
                cdb_sz);
        return 1;
    }
    return 0;
}


int erase_device(erasing_device_t *const device){

    int res, k, t, buf_sz, dio_tmp, flags, fl, sg_fd;
    int infd, outfd, blocks, in_pdt, out_pdt;

    unsigned char *wrkPos;
    unsigned char *fprint;
    //long long skip = 0;
    long long seek = 1;
    static int blk_sz = 512;
    int scsi_cdbsz_out = DEF_SCSI_CDBSZ;
    char inf[SG_PATH_SIZE];
    unsigned char *wrkBuff;
    unsigned char *wrkBuff2;

    uint8_t erasmosign[] = 
    {
    0x51, 0x75, 0x61, 0x6E, 0x74, 0x75, 0x6D, 0x20, 0x65, 0x72, 0x61, 0x73,
    0x6D, 0x6F, 0x28, 0x52, 0x29, 0x20, 0x62, 0x79, 0x20, 0x4D, 0x6F, 0x62,
    0x69, 0x6C, 0x69, 0x74, 0x79, 0x20, 0x54, 0x65, 0x61, 0x6D, 0x0a, 0x0a
    };

    strcpy(inf,device->system_path);
    blocks=128;
    int bpt = 128;
    int device_blocks = device->total_sectors;
    size_t psz = getpagesize();
    wrkBuff = malloc(blk_sz * bpt + psz);

    wrkBuff2 = malloc(512);
    long long int tfwide = blk_sz * bpt + psz;
    
    uint8_t data[tfwide];

    memset(data,0x45,sizeof(data));

    wrkPos = wrkBuff;
    memcpy(wrkPos,&data,sizeof(data));
    
    fprint = wrkBuff2;
    memcpy(fprint,&erasmosign,sizeof(erasmosign));

    //open device.
    if ((outfd = sg_cmds_open_device(inf, 1, verbose)) < 0)
    {   
        fprintf(stderr, ME " Device %s dont exist\n%s\n", inf, safe_strerror(-sg_fd));
        return EXIT_FAILURE;
    }

    dio_tmp = dio;

    for(int i = 1;i < (device_blocks / blocks);i++){

        printf("%lli of %i blocks...\n",seek, device_blocks);
        res = sg_write(outfd, wrkPos, blocks, seek, blk_sz, scsi_cdbsz_out, oflag.fua, oflag.dpo, &dio_tmp);
        seek += blocks;
    }

    int blk_remains = device_blocks - seek;

    if(seek > 0){
        printf("restantes: %lli\n", device_blocks - seek);
        for(int i = 1;i < blk_remains + 2 ;i++){
            printf("%lli de %i blocks...\n",seek, device_blocks);
            res = sg_write(outfd, wrkPos, 1, seek, blk_sz, scsi_cdbsz_out, oflag.fua, oflag.dpo, &dio_tmp);
            seek++;
        }
    }

    if (0 == (res = sg_write(outfd, fprint, 1, 0, blk_sz, scsi_cdbsz_out, oflag.fua, oflag.dpo, &dio_tmp))){
        printf("OK\n");
        device->erased=true;
    }

    free(wrkBuff);

    return 0;
}