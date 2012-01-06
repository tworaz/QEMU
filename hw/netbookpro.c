/* vim:set shiftwidth=4 ts=4 et: */
/*
 * PXA255 Psion Teklogix NetBook Pro
 *
 * Copyright (c) 2011 Peter Tworek
 *
 * This code is licensed under the GNU GPL v2.
 */

#include <sys/stat.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <zlib.h>

#include "hw.h"
#include "pxa.h"
#include "loader.h"

#include "arm-misc.h"
#include "boards.h"

/* Image is compressed with zlib */
#define BOOST_FLAG_ZLIB		(1<<16)

/* Header file used by BooSt bootloader images */
typedef struct boost_header
{
	uint32_t	branch_offset;
	uint32_t	unknown_1;
	uint32_t	image_id;
	uint32_t	platform_id;
	uint32_t	image_size;
	uint32_t	image_checksum;
	uint32_t	load_offset;
	uint32_t	flags;
	char		target_filename[16];
	char		unknown_2[16];
	char		image_name[64];
	char		image_version_string[64];
	uint32_t	mutex_bits;
	char		unknown_3[56];
	uint32_t	checksum;
} boost_hdr_t;

static unsigned swap_bytes(unsigned arg)
{
	unsigned ret;
	char *bytes = (char *)(&ret);

	bytes[3] = (arg >> 0) & 0xFF;
	bytes[2] = (arg >> 8) & 0xFF;
	bytes[1] = (arg >> 16) & 0xFF;
	bytes[0] = (arg >> 24) & 0xFF;

	return ret;
}

static void *netbookpro_zlib_decompress(const void *data, size_t data_len, size_t content_len)
{
	char *out_buf = NULL;
	z_stream zs;

	memset(&zs, 0, sizeof(z_stream));
	if (Z_OK != inflateInit(&zs)) {
		fprintf(stderr, "Failed to init zlib decompressor!\n");
		return NULL;
	}
	zs.next_in = (Bytef *)data;
	zs.avail_in = data_len;

	out_buf = malloc(content_len);
	if (NULL == out_buf) {
		fprintf(stderr, "Out of memory while allocating output "
		        "decompress buffer!\n");
		goto decompress_failed;
	}
	zs.next_out = (Bytef *)out_buf;
	zs.avail_out = content_len;

	if (Z_STREAM_END != inflate(&zs, Z_FINISH)) {
		fprintf(stderr, "Zlib decompression failed: %s\n", zs.msg);
		goto decompress_failed;
	}

    if (zs.avail_out != 0) {
        printf("Warning: image contents size doesn't match declared size!\n");
    }

	if (Z_OK != inflateEnd(&zs)) {
		fprintf(stderr, "Failed to close zlib decompressor!\n");
	}

	return out_buf;

decompress_failed:
	if (NULL != out_buf) {
		free(out_buf);
	}

	if (NULL != zs.next_in) {
		if (Z_OK != inflateEnd(&zs)) {
			fprintf(stderr, "Failed to close zlib decompressor!\n");
		}
	}

	return NULL;
}

static void netbookpro_cpu_reset(void *opaque)
{
    CPUState *env = opaque;
    const struct arm_boot_info *info = env->boot_info;

    cpu_reset(env);
    if (info)
        env->regs[15] = info->entry;
}

static struct arm_boot_info netbookpro_binfo = {
    .ram_size = (128*1024*1024)
};

static void netbookpro_init(ram_addr_t ram_size,
                const char *boot_device,
                const char *kernel_filename, const char *kernel_cmdline,
                const char *initrd_filename, const char *cpu_model)
{
    PXA2xxState *cpu;
	struct stat f_stat;
    boost_hdr_t *hdr;
    void *addr = MAP_FAILED;
    unsigned image_content_size;
    void *image_content = NULL;
    target_phys_addr_t entry;
    int fd;

    if (!cpu_model)
        cpu_model = "pxa255";

    cpu = pxa255_init(netbookpro_binfo.ram_size);

    fd = open("nBkProOs.img", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open nBkProOs.img");
        goto init_failed;
    }

	if (fstat(fd, &f_stat) != 0) {
		perror("Failed to read image stat");
		goto init_failed;
	}

	addr = mmap(NULL, f_stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		perror("Failed to memory map image");
		goto init_failed;
	}

    hdr = (boost_hdr_t *)addr;
    printf("BooSt image name: %s\n", hdr->image_name);

    if (hdr->flags & BOOST_FLAG_ZLIB) {
        image_content_size = *((unsigned *)(addr + sizeof(boost_hdr_t)));
        image_content_size = swap_bytes(image_content_size);
        image_content = netbookpro_zlib_decompress(addr + sizeof(boost_hdr_t) + 4,
                hdr->image_size, image_content_size);
    } else {
        printf("Booting of non-zlib compressed images not yet supported!\n");
        image_content = NULL;
    }

    if (image_content == NULL)
        goto init_failed;

    entry = PXA2XX_SDRAM_BASE + hdr->load_offset;

	rom_add_blob("nBkProOs.img", image_content, image_content_size, entry);

    /* Cleanup */
    free(image_content);
    image_content = NULL;
    hdr = NULL;
    munmap(addr, f_stat.st_size);
    addr = NULL;
    close(fd);

    netbookpro_binfo.entry = entry;
    cpu->env->boot_info = &netbookpro_binfo;
    qemu_register_reset(netbookpro_cpu_reset, cpu->env);

    return;

init_failed:
	if (addr != MAP_FAILED)
		munmap(addr, f_stat.st_size);

    if (fd != -1)
        close(fd);

    exit(1);
}

static QEMUMachine netbookpro_machine = {
    .name = "netbookpro",
    .desc = "Psion Teklogix NetBook Pro (PXA255)",
    .init = netbookpro_init,
};

static void netbookpro_machine_init(void)
{
    qemu_register_machine(&netbookpro_machine);
}

machine_init(netbookpro_machine_init);
