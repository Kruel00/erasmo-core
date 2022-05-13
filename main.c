#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <scsi/scsi_ioctl.h>

#include "sg_lib.h"
#include "sg_cmds.h"
#include "sg_io_linux.h"
#include "llseek.h"
#include "discos.h"

#define ME "sg_dd: "

#define MAX_SCSI_CDBSZ 16
#define SENSE_BUFF_LEN 32 /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000 /* 60,000 millisecs == 60 seconds */
#define STR_SZ 1024
#define DEF_BLOCKS_PER_TRANSFER 128
#define INOUTF_SZ 512
#define FT_OTHER 1 /* filetype is probably normal */
#define DEF_SCSI_CDBSZ 10
#define DEF_BLOCK_SIZE 512
#define RCAP16_REPLY_LEN 32
#define READ_CAP_REPLY_LEN 8
#define O_RDWR 02
#define MIN_RESERVED_SIZE 8192
#define RCAP_REPLY_LEN 8
#define SAFE_STD_INQ_RESP_LEN 36
#define MX_ALLOC_LEN (0xc000 + 0x80)

//scann
#define INQ_REPLY_LEN 36
#define INQ_CMD_LEN 6
#define MAX_ERRORS 4


//inq
#define DEF_ALLOC_LEN 252
#define SUPPORTED_VPDS_VPD 0x0
#define UNIT_SERIAL_NUM_VPD 0x80


//scan
static const char * sysfs_sg_dir = "/sys/class/scsi_generic";
static unsigned char inqCmdBlk[INQ_CMD_LEN] = {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};

struct flags_t
{
    int append;
    int coe;
    int direct;
    int dpo;
    int dsync;
    int excl;
    int fua;
    int sgio;
};

static struct flags_t iflag;
static struct flags_t oflag;

static int read_longs = 0;
static int verbose = 0;
static int recovered_errs = 0;
static int unrecovered_errs = 0;
static int sum_of_resids = 0;
static int do_time = 0;
static int blk_sz = 0;
static int start_tm_valid = 0;
static long long req_count = 0;
static long long dd_count = -1;
static long long in_full = 0;
static long long out_full = 0;
static int out_partial = 0;
static int in_partial = 0;


static unsigned char rsp_buff[MX_ALLOC_LEN + 1];

//inq
static char xtra_buff[MX_ALLOC_LEN + 1];

struct timeval start_tm;

static int sg_read(int sg_fd, unsigned char *buff, int blocks, long long from_block, int bs, int cdbsz, int fua, int dpo, int *diop, int pdt);
static int sg_write(int sg_fd, unsigned char *buff, int blocks, long long to_block, int bs, int cdbsz, int fua, int dpo, int *diop);
static int sg_read_low(int sg_fd, unsigned char *buff, int blocks, long long from_block, int bs, int cdbsz, int fua, int dpo, int pdt, int *diop, unsigned long long *io_addrp);
static int sg_build_scsi_cdb(unsigned char *cdbp, int cdb_sz, unsigned int blocks, long long start_block, int write_true, int fua, int dpo);
void usage();
static void siginfo_handler(int sig);
static void interrupt_handler(int sig);
static void install_handler(int sig_num, void (*sig_handler)(int sig));
static void calc_duration_throughput(int contin);
static void print_stats(const char *str);
static int scsi_read_capacity(int sg_fd, long long *num_sect, int *sect_sz);
static int fetch_unit_serial_num(int sg_fd, char * obuff, int obuff_len, int verbose);
int scsi_inq(int sg_fd, unsigned char * inqBuff);

int main(int argc, char *argv[])
{
    int lba = 0;
    long long skip = 0;
    long long seek = 0;
    int ibs = 0;
    char *key;
    char *buf;
    int do_time = 1;
    int bpt = DEF_BLOCKS_PER_TRANSFER;
    char inf[INOUTF_SZ];
    int in_type = FT_OTHER;
    char outf[INOUTF_SZ];
    int dio = 0;
    int out_type = FT_OTHER;
    int scsi_cdbsz_in = DEF_SCSI_CDBSZ;
    int res, k, t, buf_sz, dio_tmp, flags, fl;
    
    int scsi_cdbsz_out = DEF_SCSI_CDBSZ;
    char str[STR_SZ];
    int in_sect_sz, out_sect_sz;
    iflag.sgio = 1;
    long long in_num_sect = -1;
    unsigned char *wrkBuff;
    static long long dd_count = 0; // setors to read
    int infd, outfd, blocks, in_pdt, out_pdt;
    unsigned char *wrkPos;
    struct sg_simple_inquiry_resp sir;
    int do16 = 0;
    int blocks_per;
    int dio_incomplete = 0;

    
    // read cap
    int sg_fd;
    int pmi = 0;
    unsigned char resp_buff[RCAP16_REPLY_LEN];
    unsigned int last_blk_addr, block_size;
    unsigned long long llba = 0;
    unsigned long long u, llast_blk_addr;
    unsigned long long total_sz = last_blk_addr + 1;
    double sz_mb, sz_gb;


    //inqui
    int do_verbose, reserved_cmddt;
    int res2, len, act_len, pqual, peri_type, ansi_version, ret, j, support_num,num;
    
    inf[0] = '\0';
    outf[0] = '\0';

    if (argc < 2)
    {
        usage();
        return 1;
    }

    for (k = 1; k < argc; k++)
    {
        if (argv[k])
        {
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
            if (*argv[k] == '/')
            {
                strcpy(inf, argv[k]);
            }
            strncpy(str, argv[k], STR_SZ);
            str[STR_SZ - 1] = '\0';
        }
    }

    install_handler(SIGINT, interrupt_handler);
    install_handler(SIGQUIT, interrupt_handler);
    install_handler(SIGPIPE, interrupt_handler);
    install_handler(SIGUSR1, siginfo_handler);

    infd = STDIN_FILENO;
    outfd = STDOUT_FILENO;
    in_pdt = -1;
    out_pdt = -1;
    oflag.sgio = 1;
    oflag.direct = 0;
    in_num_sect = -1;

    blocks = bpt;

    blk_sz = DEF_BLOCK_SIZE;

    

    if ((sg_fd = sg_cmds_open_device(inf, (do16 ? 0 /* rw */ : 1), verbose)) < 0)
    {
        fprintf(stderr, ME "error opening file: %s: %s\n", inf,
                safe_strerror(-sg_fd));
        return 1;
    }

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

    res2 = sg_ll_inquiry(sg_fd, 0, 0, 0, rsp_buff, SAFE_STD_INQ_RESP_LEN, 0, verbose);

    if (0 == res) {
        pqual = (rsp_buff[0] & 0xe0) >> 5;
        len = rsp_buff[4] + 5;
        ansi_version = rsp_buff[2] & 0x7;
        reserved_cmddt = rsp_buff[4];
        support_num = rsp_buff[1] & 7;
        num = rsp_buff[5];
        peri_type = rsp_buff[0] & 0x1f;
        int skip = 8;

        for(int i = 0;i<4;i++){
            memcpy(xtra_buff, &rsp_buff[skip],8);
            xtra_buff[8] = '\0';
            printf("Data: %s\n",xtra_buff); 
            skip += 8;
        }

        if(fetch_unit_serial_num(sg_fd, xtra_buff, sizeof(xtra_buff), verbose)==0)
            printf("Unit serial number: %s\n", xtra_buff);
    }

    storage_device_t disco;
    strcpy(disco.filename,inf);
    disco.sectors = last_blk_addr;
    disco.block_size = block_size;

    printf("storage device: %s\n",disco.filename);
    printf("Sectors: %lu\nBlock Size: %u bytes\n", disco.sectors, disco.block_size);
    total_sz = block_size * last_blk_addr;
    sz_mb = ((double)(last_blk_addr + 1) * block_size) / (double)(1048576);
    sz_gb = ((double)(last_blk_addr + 1) * block_size) / (double)(1000000000L);
    printf("Device size: %llu bytes, %.1f MiB, %.2f GB\n",total_sz, sz_mb, sz_gb);


    /*
    size_t psz = getpagesize();
    wrkBuff = malloc(blk_sz * bpt + psz);
    wrkPos = (unsigned char *)(((unsigned long)wrkBuff + psz - 1) & (~(psz - 1)));

    blocks_per = bpt;
    req_count = 1;
    infd = sg_fd;
    dd_count = disco.sectors ; //disco.sectors;

    while (dd_count > 0)
    {
        dio_tmp = dio;
            res = sg_read(infd, wrkPos, blocks, skip, blk_sz, scsi_cdbsz_in, iflag.fua, iflag.dpo, &dio_tmp, in_pdt);
            printf("remaining blocks: %lli\n",dd_count);
            //system("clear");
            if (-2 == res)
            { // ENOMEM, find what's available+try that
                if (ioctl(infd, SG_GET_RESERVED_SIZE, &buf_sz) < 0)
                {
                    perror("RESERVED_SIZE ioctls failed");
                    break;
                }
                if (buf_sz < MIN_RESERVED_SIZE)
                    buf_sz = MIN_RESERVED_SIZE;
                blocks_per = (buf_sz + blk_sz - 1) / blk_sz;
                printf("blocks_per:%i\n",blocks_per);
                if (blocks_per < blocks)
                {
                    blocks = blocks_per;
                    fprintf(stderr, "Reducing read to %d blocks per "
                                    "loop\n",
                            blocks_per);
                    res = sg_read(infd, wrkPos, blocks, skip, blk_sz,
                                  scsi_cdbsz_in, iflag.fua, iflag.dpo,
                                  &dio_tmp, in_pdt);
                }
            }
            if (res < 0)
            {
                fprintf(stderr, "sg_read failed,%s at or after lba=%lld "
                                "[0x%llx]\n",
                        ((-2 == res) ? " try reducing bpt," : ""), skip, skip);
                break;
            }
            else
            {
                if (res < blocks)
                {
                    dd_count = 0; // force exit after write
                    blocks = res;
                }
                in_full += blocks;
                if (dio && (0 == dio_tmp))
                    dio_incomplete++;
            }
            dd_count -= blocks;
            skip += blocks;
            seek += blocks;
    }*/

    return 0;
}

void usage()
{
    printf("\tapp usage as no been set \n\tbut u can imagine here are a important info\n");
}

/* Returns >= 0 -> number of blocks read, -1 -> unrecoverable error,
   -2 -> recoverable (ENOMEM) */
static int sg_read(int sg_fd, unsigned char *buff, int blocks, long long from_block, int bs, int cdbsz, int fua, int dpo, int *diop, int pdt)
{
    unsigned long long io_addr;
    long long lba;
    int res, blks, cont, xferred;
    unsigned char *bp;

    for (xferred = 0, blks = blocks, lba = from_block, bp = buff; blks > 0; blks = blocks - xferred)
    {
        io_addr = 0;
        cont = 0;
        res = sg_read_low(sg_fd, bp, blks, lba, bs, cdbsz, fua, dpo, pdt, diop, &io_addr);

        switch (res)
        {
        case 0:
            return xferred + blks;
        case 1:
            return -2;
        case 2:
            fprintf(stderr,
                    "Unit attention, media changed, continuing (r)\n");
            cont = 1;
            break;
        case -1:
            goto err_out;
        case -2:
            iflag.coe = 0;
            goto err_out;
        case 3:
            break; /* unrecovered read error at lba=io_addr */
        default:
            fprintf(stderr, ">> unexpected result=%d from sg_read_low()\n",
                    res);
            return -1;
        }
        if (cont)
            continue;
        if ((io_addr < (unsigned long long)lba) ||
            (io_addr >= (unsigned long long)(lba + blks)))
        {
            fprintf(stderr, "  Unrecovered error lba 0x%llx not in "
                            "correct range:\n\t[0x%llx,0x%llx]\n",
                    io_addr,
                    (unsigned long long)lba,
                    (unsigned long long)(lba + blks - 1));
            goto err_out;
        }
        blks = (int)(io_addr - (unsigned long long)lba);
        if (blks > 0)
        {
            res = sg_read_low(sg_fd, bp, blks, lba, bs, cdbsz, fua, dpo,
                              pdt, diop, &io_addr);
            switch (res)
            {
            case 0:
                break;
            case 1:
                fprintf(stderr, "ENOMEM again, unexpected (r)\n");
                return -1;
            case 2:
                fprintf(stderr,
                        "Unit attention, media changed, unexpected (r)\n");
                return -1;
            case -2:
                iflag.coe = 0;
                goto err_out;
            case -1:
            case 3:
                goto err_out;
            default:
                fprintf(stderr, ">> unexpected result=%d from "
                                "sg_read_low() 2\n",
                        res);
                return -1;
            }
        }
        xferred += blks;
        if (!iflag.coe)
            return xferred; /* give up at block before problem unless 'coe' */
        if (bs < 32)
        {
            fprintf(stderr, ">> bs=%d too small for read_long\n", bs);
            return -1; /* nah, block size can't be that small */
        }
        bp += (blks * bs);
        lba += blks;
        if ((0 != pdt) || (iflag.coe < 2))
        {
            fprintf(stderr, ">> unrecovered read error at blk=%lld, "
                            "pdt=%d, use zeros\n",
                    lba, pdt);
            memset(bp, 0, bs);
        }
        else if (io_addr < UINT_MAX)
        {
            unsigned char *buffp;
            int offset, nl, r, ok, corrct;

            buffp = malloc(bs * 2);
            if (NULL == buffp)
            {
                fprintf(stderr, ">> heap problems\n");
                return -1;
            }
            corrct = (iflag.coe > 2) ? 1 : 0;
            res = sg_ll_read_long10(sg_fd, corrct, lba, buffp, bs + 8, &offset, 1, verbose);
            ok = 0;
            switch (res)
            {
            case 0:
                ok = 1;
                ++read_longs;
                break;
            case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:
                nl = bs + 8 - offset;
                if ((nl < 32) || (nl > (bs * 2)))
                {
                    fprintf(stderr, ">> read_long(10) len=%d unexpected\n",
                            nl);
                    break;
                }
                if (0 == r)
                {
                    ok = 1;
                    ++read_longs;
                    break;
                }
                else
                    fprintf(stderr, ">> unexpected result=%d on second "
                                    "read_long(10)\n",
                            r);
                break;
            case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, ">> read_long(10) not supported\n");
                break;
            case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, ">> read_long(10) bad cdb field\n");
                break;
            default:
                fprintf(stderr, ">> read_long(10) problem\n");
                break;
            }
            if (ok)
                memcpy(bp, buffp, bs);
            else
                memset(bp, 0, bs);
            free(buffp);
        }
        else
        {
            fprintf(stderr, ">> read_long(10) cannot handle blk=%lld, use zeros\n", lba);
            memset(bp, 0, bs);
        }
        ++xferred;
        ++blks;
        bp += bs;
        ++lba;
    }
    return xferred;

err_out:
    if (iflag.coe)
    {
        memset(bp, 0, bs * blks);
        fprintf(stderr, ">> unable to read at blk=%lld for %d bytes, use zeros\n", lba, bs * blks);
        return xferred + blks; /* fudge success */
    }
    else
        return -1;
}

/* 0 -> successful, -1 -> unrecoverable error, -2 -> recoverable (ENOMEM),
   -3 -> try again (media changed unit attention) */
static int sg_write(int sg_fd, unsigned char *buff, int blocks,
                    long long to_block, int bs, int cdbsz, int fua, int dpo,
                    int *diop)
{
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
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)to_block;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    if (verbose > 1)
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
    switch (sg_err_category3(&io_hdr))
    {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        ++recovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr,
                                           &io_addr);
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

/* 0 -> successful, 1 -> recoverable (ENOMEM), 2 -> try again (ua),
   3 -> unrecoverable error with io_addr, -2 -> ioctl or request error,
  -1 -> other SCSI error */
static int sg_read_low(int sg_fd, unsigned char *buff, int blocks, long long from_block, int bs, int cdbsz,
                       int fua, int dpo, int pdt, int *diop, unsigned long long *io_addrp)
{
    unsigned char rdCmd[MAX_SCSI_CDBSZ];
    unsigned char senseBuff[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int res, k, info_valid;

    if (sg_build_scsi_cdb(rdCmd, cdbsz, blocks, from_block, 0, fua, dpo))
    {
        fprintf(stderr, ME "bad rd cdb build, from_block=%lld, blocks=%d\n",
                from_block, blocks);
        return -2;
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = cdbsz;
    io_hdr.cmdp = rdCmd;
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = bs * blocks;
    io_hdr.dxferp = buff;
    io_hdr.mx_sb_len = SENSE_BUFF_LEN;
    io_hdr.sbp = senseBuff;
    io_hdr.timeout = DEF_TIMEOUT;
    io_hdr.pack_id = (int)from_block;
    if (diop && *diop)
        io_hdr.flags |= SG_FLAG_DIRECT_IO;

    if (verbose > 2)
    {
        fprintf(stderr, "    read cdb: ");
        for (k = 0; k < cdbsz; ++k)
            fprintf(stderr, "%02x ", rdCmd[k]);
        fprintf(stderr, "\n");
    }
    while (((res = ioctl(sg_fd, SG_IO, &io_hdr)) < 0) && (EINTR == errno))
        ;
    if (res < 0)
    {
        if (ENOMEM == errno)
            return 1;
        perror("reading (SG_IO) on sg device, error");
        return -2;
    }
    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    switch (sg_err_category3(&io_hdr))
    {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:
        ++recovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr,
                                           io_addrp);
        if (info_valid)
        {
            fprintf(stderr, "    lba of last recovered error in this "
                            "READ=0x%llx\n",
                    *io_addrp);
            if (verbose > 1)
                sg_chk_n_print3("reading", &io_hdr, 1);
        }
        else
        {
            fprintf(stderr, "Recovered error: [no info] reading from "
                            "block=0x%llx, num=%d\n",
                    from_block, blocks);
            sg_chk_n_print3("reading", &io_hdr, verbose > 1);
        }
        break;
    case SG_LIB_CAT_MEDIA_CHANGED:
        if (verbose > 1)
            sg_chk_n_print3("reading", &io_hdr, 1);
        return 2;
    case SG_LIB_CAT_MEDIUM_HARD:
        if (verbose > 1)
            sg_chk_n_print3("reading", &io_hdr, 1);
        ++unrecovered_errs;
        info_valid = sg_get_sense_info_fld(io_hdr.sbp, io_hdr.sb_len_wr,
                                           io_addrp);
        if ((info_valid) || ((5 == pdt) && (*io_addrp > 0)))
            return 3; /* MMC devices don't necessarily set VALID bit */
        else
        {
            fprintf(stderr, "Medium or hardware error but no lba of failure"
                            " given\n");
            return -1;
        }
        break;
    default:
        ++unrecovered_errs;
        sg_chk_n_print3("reading", &io_hdr, verbose > 1);
        return -1;
    }
    if (diop && *diop &&
        ((io_hdr.info & SG_INFO_DIRECT_IO_MASK) != SG_INFO_DIRECT_IO))
        *diop = 0; /* flag that dio not done (completely) */
    sum_of_resids += io_hdr.resid;
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

static void interrupt_handler(int sig)
{
    struct sigaction sigact;

    sigact.sa_handler = SIG_DFL;
    sigemptyset(&sigact.sa_mask);
    sigact.sa_flags = 0;
    sigaction(sig, &sigact, NULL);
    fprintf(stderr, "Interrupted by signal,");
    if (do_time)
        calc_duration_throughput(0);
    print_stats("");
    kill(getpid(), sig);
}

static void siginfo_handler(int sig)
{
    sig = sig; /* dummy to stop -W warning messages */
    fprintf(stderr, "Progress report, continuing ...\n");
    if (do_time)
        calc_duration_throughput(1);
    print_stats("  ");
}

static void install_handler(int sig_num, void (*sig_handler)(int sig))
{
    struct sigaction sigact;
    sigaction(sig_num, NULL, &sigact);
    if (sigact.sa_handler != SIG_IGN)
    {
        sigact.sa_handler = sig_handler;
        sigemptyset(&sigact.sa_mask);
        sigact.sa_flags = 0;
        sigaction(sig_num, &sigact, NULL);
    }
}

static void calc_duration_throughput(int contin)
{
    struct timeval end_tm, res_tm;
    double a, b;

    if (start_tm_valid && (start_tm.tv_sec || start_tm.tv_usec))
    {
        gettimeofday(&end_tm, NULL);
        res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
        res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
        if (res_tm.tv_usec < 0)
        {
            --res_tm.tv_sec;
            res_tm.tv_usec += 1000000;
        }
        a = res_tm.tv_sec;
        a += (0.000001 * res_tm.tv_usec);
        b = (double)blk_sz * (req_count - dd_count);
        fprintf(stderr, "time to transfer data%s: %d.%06d secs",
                (contin ? " so far" : ""), (int)res_tm.tv_sec,
                (int)res_tm.tv_usec);
        if ((a > 0.00001) && (b > 511))
            fprintf(stderr, " at %.2f MB/sec\n", b / (a * 1000000.0));
        else
            fprintf(stderr, "\n");
    }
}

static void print_stats(const char *str)
{
    if (0 != dd_count)
        fprintf(stderr, "  remaining block count=%lld\n", dd_count);
    fprintf(stderr, "%s%lld+%d records in\n", str, in_full - in_partial, in_partial);
    fprintf(stderr, "%s%lld+%d records out\n", str, out_full - out_partial, out_partial);
    if (recovered_errs > 0)
        fprintf(stderr, "%s%d recovered errors\n", str, recovered_errs);
    if (iflag.coe || oflag.coe)
    {
        fprintf(stderr, "%s%d unrecovered errors\n", str, unrecovered_errs);
        fprintf(stderr, "%s%d read_longs fetched part of unrecovered read errors\n", str, read_longs);
    }
    else if (unrecovered_errs)
        fprintf(stderr, "%s%d unrecovered read error(s)\n", str, unrecovered_errs);
}

/* Return of 0 -> success, SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_MEDIA_CHANGED -> media changed, SG_LIB_CAT_ILLEGAL_REQ
 * -> bad field in cdb, -1 -> other failure */

static int scsi_read_capacity(int sg_fd, long long *num_sect, int *sect_sz)
{
    int k, res;
    unsigned int ui;
    unsigned char rcBuff[RCAP16_REPLY_LEN];
    int verb;

    verb = (verbose ? verbose - 1 : 0);
    res = sg_ll_readcap_10(sg_fd, 0, 0, rcBuff, READ_CAP_REPLY_LEN, 0, verb);
    if (0 != res)
        return res;

    if ((0xff == rcBuff[0]) && (0xff == rcBuff[1]) && (0xff == rcBuff[2]) &&
        (0xff == rcBuff[3]))
    {
        long long ls;

        res = sg_ll_readcap_16(sg_fd, 0, 0, rcBuff, RCAP16_REPLY_LEN, 0,
                               verb);
        if (0 != res)
            return res;
        for (k = 0, ls = 0; k < 8; ++k)
        {
            ls <<= 8;
            ls |= rcBuff[k];
        }
        *num_sect = ls + 1;
        *sect_sz = (rcBuff[8] << 24) | (rcBuff[9] << 16) |
                   (rcBuff[10] << 8) | rcBuff[11];
    }
    else
    {
        ui = ((rcBuff[0] << 24) | (rcBuff[1] << 16) | (rcBuff[2] << 8) |
              rcBuff[3]);
        /* take care not to sign extend values > 0x7fffffff */
        *num_sect = (long long)ui + 1;
        *sect_sz = (rcBuff[4] << 24) | (rcBuff[5] << 16) |
                   (rcBuff[6] << 8) | rcBuff[7];
    }
    
    if (verbose)
        fprintf(stderr, "      number of blocks=%lld [0x%llx], block "
                        "size=%d\n",
                *num_sect, *num_sect, *sect_sz);
    return 0;
}


/* Returns 0 if Unit Serial Number VPD page contents found, else -1 */
static int fetch_unit_serial_num(int sg_fd, char * obuff, int obuff_len, int verbose)
{
    int sz, len, k;
    unsigned char b[DEF_ALLOC_LEN];

    sz = sizeof(b);
    memset(b, 0xff, 4); /* guard against empty response */
    /* first check if unit serial number VPD page is supported */
    if ((0 == sg_ll_inquiry(sg_fd, 0, 1, SUPPORTED_VPDS_VPD, b, sz, 0, verbose)) && (SUPPORTED_VPDS_VPD == b[1]) && (0x0 == b[2])) 
    {
        len = b[3];
        for (k = 0; k < len; ++k) {
            if (UNIT_SERIAL_NUM_VPD == b[k + 4])
                break;
        }
        if ((k < len) &&
            (0 == sg_ll_inquiry(sg_fd, 0, 1, UNIT_SERIAL_NUM_VPD, b, sz, 0, verbose))) {
            len = b[3];
            len = (len < (obuff_len - 1)) ? len : (obuff_len - 1);
            if ((UNIT_SERIAL_NUM_VPD == b[1]) && (len > 0)) {
                memcpy(obuff, b + 4, len);
                obuff[len] = '\0';
                return 0;
            }
        }
    }
    return -1;
}

struct lscsi_ioctl_command {
        unsigned int inlen;  /* _excluding_ scsi command length */
        unsigned int outlen;
        unsigned char data[1];  /* was 0 but that's not ISO C!! */
                /* on input, scsi command starts here then opt. data */
};

int scsi_inq(int sg_fd, unsigned char * inqBuff)
{
    int res;
    unsigned char buff[512];
    struct lscsi_ioctl_command * sicp = (struct lscsi_ioctl_command *)buff;

    memset(buff, 0, sizeof(buff));
    sicp->inlen = 0;
    sicp->outlen = INQ_REPLY_LEN;
    memcpy(sicp->data, inqCmdBlk, INQ_CMD_LEN);
    res = ioctl(sg_fd, SCSI_IOCTL_SEND_COMMAND, sicp);
    if (0 == res)
        memcpy(inqBuff, sicp->data, INQ_REPLY_LEN);
    return res;
}