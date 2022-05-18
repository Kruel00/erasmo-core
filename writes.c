//gcc -o writa writes.c sg_io_linux.c sg_cmds.c sg_lib.c sg_pt_linux.c -I./include

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <scsi/scsi_ioctl.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdint.h>

#include "sg_lib.h"
#include "sg_cmds.h"
#include "sg_io_linux.h"
#include "llseek.h"


#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */
#define MAX_SCSI_CDBSZ 16
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define ME "erasmo"
#define SG_DD_BYPASS 999        /* failed but coe set */
#define SG_PATH_SIZE 512


static int cmd_timeout = DEF_TIMEOUT;   /* in milliseconds */
static bool do_verify = false;          /* when false: do copy */
#define DEF_SCSI_CDBSZ 10
static uint32_t glob_pack_id = 0;       /* pre-increment */
static int verbose = 0;
static int recovered_errs = 0;
static int unrecovered_errs = 0;
static int miscompare_errs = 0;
static struct flags_t iflag;
static struct flags_t oflag;
static int blk_sz = 512;
int dio = 0;

static int sg_build_scsi_cdb(unsigned char *cdbp, int cdb_sz, unsigned int blocks, long long start_block, int write_true, int fua, int dpo);
static int sg_write(int sg_fd, unsigned char *buff, int blocks, long long to_block, int bs, int cdbsz, int fua, int dpo, int *diop);

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


int main(){

    int res, k, t, buf_sz, dio_tmp, flags, fl, sg_fd;
    int infd, outfd, blocks, in_pdt, out_pdt;

    unsigned char *wrkPos;
    unsigned char *fprint;
    long long skip = 0;
    long long seek = 0;
    static int blk_sz = 512;
    int scsi_cdbsz_out = DEF_SCSI_CDBSZ;
    char inf[SG_PATH_SIZE];
    unsigned char *wrkBuff;
    unsigned char *wrkBuff2;

    uint8_t firma[] = 
    {
    0x51, 0x75, 0x61, 0x6E, 0x74, 0x75, 0x6D, 0x20, 0x65, 0x72, 0x61, 0x73,
    0x6D, 0x6F, 0x28, 0x52, 0x29, 0x20, 0x62, 0x79, 0x20, 0x4D, 0x6F, 0x62,
    0x69, 0x6C, 0x69, 0x74, 0x79, 0x20, 0x54, 0x65, 0x61, 0x6D, 0x0a, 0x0a
    };

    uint8_t data[512];

    memset(data,0x30,sizeof(data));

    strcpy(inf,"/dev/sg4");
    blocks=100;
    int bpt = 128;
    size_t psz = getpagesize();
    wrkBuff = malloc(blk_sz * bpt + psz);
    wrkBuff2 = malloc(blk_sz * bpt + psz);

    wrkPos = wrkBuff;
    memcpy(wrkPos,&data,sizeof(data));

    fprint = wrkBuff2;
    memcpy(fprint,&firma,sizeof(firma));

    //open device.
    printf("\n");    

    if ((outfd = sg_cmds_open_device(inf, 1, verbose)) < 0)
    {   
        fprintf(stderr, ME " Device %s dont exist\n%s\n", inf, safe_strerror(-sg_fd));
        
        return EXIT_FAILURE;
    }

    dio_tmp = dio;

    for(int i = 0;i < blocks;i++){
    res = sg_write(outfd, wrkPos, blocks, seek, blk_sz, scsi_cdbsz_out, oflag.fua, oflag.dpo, &dio_tmp);
        skip++;
        seek++;
    printf("Block: %i\n",i);
    }

    res = sg_write(outfd, fprint, 1, 0, blk_sz, scsi_cdbsz_out, oflag.fua, oflag.dpo, &dio_tmp);

    free(wrkBuff);

    return 0;
}


/* 0 -> successful, -1 -> unrecoverable error, -2 -> recoverable (ENOMEM),
   -3 -> try again (media changed unit attention) */
static int sg_write(int sg_fd, unsigned char *buff, int blocks, long long to_block, int bs, int cdbsz, int fua, int dpo, int *diop){
    /*for(int i =0; i<7;i++){
        printf("%c",buff[i]);
    }*/
    printf("\n");
    unsigned char wrCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res, k, info_valid;
    unsigned long long io_addr = 0;

    if (sg_build_scsi_cdb(wrCmd, cdbsz, blocks, to_block, 1, fua, dpo))
    {
        fprintf(stderr, ME "bad wr cdb build, to_block=%lld, blocks=%d\n", to_block, blocks);
        return -1;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = wrCmd;
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    printf("%p\n",io_hdr.dxferp);
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
