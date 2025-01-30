// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2022 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#ifdef WITH_ANDROID
#include <stdio.h>
#include <sys/stat.h>
#include "erofs/du_list.h"

#define EROFS_MODNAME	"erofs du_list"
#include "erofs/print.h"

static FILE *du_list_fp;

int erofs_droid_dulist_fopen(void)
{
	du_list_fp = fopen(cfg.du_list_file, "w");

	if (!du_list_fp)
		return -1;
	return 0;
}

void erofs_droid_dulist_fclose(void)
{
	if (!du_list_fp)
		return;

	fclose(du_list_fp);
	du_list_fp = NULL;
}

static void dulist_write(const char *path, erofs_off_t i_size,
			    unsigned short idata_size,
			    erofs_blk_t nblocks)
{
	const char *fspath = erofs_fspath(path);

	fprintf(du_list_fp, "%12llu %12llu ", (unsigned long long)i_size,
				(unsigned long long)nblocks * EROFS_BLKSIZ);

	if (cfg.mount_point[0] != '\0')
		fprintf(du_list_fp, "/%s", cfg.mount_point);

	if (fspath[0] != '/')
		fprintf(du_list_fp, "/");

	fprintf(du_list_fp, "%s\n", fspath);
}

void erofs_droid_dulist_write(struct erofs_inode *inode)
{
	erofs_blk_t nblks;

	if (!du_list_fp || !cfg.mount_point)
		return;
	if (is_inode_layout_compression(inode))
		nblks = inode->u.i_blocks;
	else
		nblks = BLK_ROUND_UP(inode->i_size);

	dulist_write(inode->i_srcpath, inode->i_size,
			inode->idata_size, nblks);
}
#endif
