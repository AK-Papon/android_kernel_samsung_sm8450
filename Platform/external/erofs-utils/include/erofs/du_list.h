/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2022 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#ifndef __EROFS_DU_LIST_H
#define __EROFS_DU_LIST_H

#ifdef __cplusplus
extern "C"
{
#endif

#include "internal.h"

#ifdef WITH_ANDROID
int erofs_droid_dulist_fopen(void);
void erofs_droid_dulist_fclose(void);
void erofs_droid_dulist_write(struct erofs_inode *inode);
#else
void erofs_droid_dulist_write(struct erofs_inode *inode) {}
#endif
#ifdef __cplusplus
}
#endif

#endif
