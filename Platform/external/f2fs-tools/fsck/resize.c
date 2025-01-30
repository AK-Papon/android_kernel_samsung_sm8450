/**
 * resize.c
 *
 * Copyright (c) 2015 Jaegeuk Kim <jaegeuk@kernel.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include "fsck.h"

static void migrate_main(struct f2fs_sb_info *sbi, unsigned int offset)
{
	void *raw = calloc(BLOCK_SZ, 1);
	struct seg_entry *se;
	block_t from, to;
	int i, j, ret;
	struct f2fs_summary sum;

	ASSERT(raw != NULL);

	for (i = MAIN_SEGS(sbi) - 1; i >= 0; i--) {
		se = get_seg_entry(sbi, i);
		if (!se->valid_blocks)
			continue;

		for (j = sbi->blocks_per_seg - 1; j >= 0; j--) {
			if (!f2fs_test_bit(j, (const char *)se->cur_valid_map))
				continue;

			from = START_BLOCK(sbi, i) + j;
			ret = dev_read_block(raw, from);
			ASSERT(ret >= 0);

			to = from + offset;
			ret = dev_write_block(raw, to);
			ASSERT(ret >= 0);

			get_sum_entry(sbi, from, &sum);

			if (IS_DATASEG(se->type))
				update_data_blkaddr(sbi, le32_to_cpu(sum.nid),
					le16_to_cpu(sum.ofs_in_node), to);
			else
				update_nat_blkaddr(sbi, 0,
						le32_to_cpu(sum.nid), to);
		}
	}
	free(raw);
	DBG(0, "Info: Done to migrate Main area: main_blkaddr = 0x%x -> 0x%x\n",
				START_BLOCK(sbi, 0),
				START_BLOCK(sbi, 0) + offset);
}

static void move_ssa(struct f2fs_sb_info *sbi, unsigned int segno,
					block_t new_sum_blk_addr)
{
	struct f2fs_summary_block *sum_blk;
	int type;

	sum_blk = get_sum_block(sbi, segno, &type);
	if (type < SEG_TYPE_MAX) {
		int ret;

		ret = dev_write_block(sum_blk, new_sum_blk_addr);
		ASSERT(ret >= 0);
		DBG(1, "Write summary block: (%d) segno=%x/%x --> (%d) %x\n",
				type, segno, GET_SUM_BLKADDR(sbi, segno),
				IS_SUM_NODE_SEG(sum_blk->footer),
				new_sum_blk_addr);
	}
	if (type == SEG_TYPE_NODE || type == SEG_TYPE_DATA ||
			type == SEG_TYPE_MAX) {
		free(sum_blk);
	}
	DBG(1, "Info: Done to migrate SSA blocks\n");
}

static void migrate_ssa(struct f2fs_sb_info *sbi,
		struct f2fs_super_block *new_sb, unsigned int offset)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	block_t old_sum_blkaddr = get_sb(ssa_blkaddr);
	block_t new_sum_blkaddr = get_newsb(ssa_blkaddr);
	block_t end_sum_blkaddr = get_newsb(main_blkaddr);
	block_t expand_sum_blkaddr = new_sum_blkaddr +
					MAIN_SEGS(sbi) - offset;
	block_t blkaddr;
	int ret;
	void *zero_block = calloc(BLOCK_SZ, 1);
	ASSERT(zero_block);

	if (offset && new_sum_blkaddr < old_sum_blkaddr + offset) {
		blkaddr = new_sum_blkaddr;
		while (blkaddr < end_sum_blkaddr) {
			if (blkaddr < expand_sum_blkaddr) {
				move_ssa(sbi, offset++, blkaddr++);
			} else {
				ret = dev_write_block(zero_block, blkaddr++);
				ASSERT(ret >=0);
			}
		}
	} else {
		blkaddr = end_sum_blkaddr - 1;
		offset = MAIN_SEGS(sbi) - 1;
		while (blkaddr >= new_sum_blkaddr) {
			if (blkaddr >= expand_sum_blkaddr) {
				ret = dev_write_block(zero_block, blkaddr--);
				ASSERT(ret >=0);
			} else {
				move_ssa(sbi, offset--, blkaddr--);
			}
		}
	}

	DBG(0, "Info: Done to migrate SSA blocks: sum_blkaddr = 0x%x -> 0x%x\n",
				old_sum_blkaddr, new_sum_blkaddr);
	free(zero_block);
}

static void migrate_ssa_safe(struct f2fs_sb_info *sbi,
		struct f2fs_super_block *new_sb, unsigned int offset)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct f2fs_checkpoint *cp = F2FS_CKPT(sbi);
	block_t old_sum_blkaddr = get_sb(ssa_blkaddr);
	block_t old_offset_blkaddr = old_sum_blkaddr + offset;
	block_t new_sum_blkaddr = get_newsb(ssa_blkaddr);
	block_t end_sum_blkaddr = get_newsb(main_blkaddr);
	block_t expand_sum_blkaddr = new_sum_blkaddr +
		TOTAL_SEGS(sbi) - offset;
	block_t blkaddr;
	unsigned int blocks_per_seg = 1 << get_sb(log_blocks_per_seg);
	unsigned int seg_size = (1 << get_sb(log_blocksize)) * blocks_per_seg;
	int seg, target_segs;
	int ret, type, blk;
	void *ssa = calloc(F2FS_BLKSIZE, 1 << get_sb(log_blocks_per_seg));
	void *zero_block = calloc(BLOCK_SZ, 1);
	ASSERT(ssa);
	ASSERT(zero_block);

	ASSERT(offset);

	for (type = 0; type < NR_CURSEG_NODE_TYPE; type++) {
		struct curseg_info *curseg;
		int segno;
		segno = get_cp(cur_node_segno[type]);
		curseg = CURSEG_I(sbi, CURSEG_HOT_NODE + type);
		ret = dev_write_block(curseg->sum_blk, GET_SUM_BLKADDR(sbi, segno));
		ASSERT(ret >= 0);
	}
	for (type = 0; type < NR_CURSEG_DATA_TYPE; type++) {
		struct curseg_info *curseg;
		int segno;
		segno = get_cp(cur_data_segno[type]);
		curseg = CURSEG_I(sbi, type);
		ret = dev_write_block(curseg->sum_blk, GET_SUM_BLKADDR(sbi, segno));
		ASSERT(ret >= 0);
	}

	target_segs = SEG_ALIGN(end_sum_blkaddr - new_sum_blkaddr);
	old_offset_blkaddr = old_sum_blkaddr + offset;
	for (seg = target_segs - 1; seg >= 0; seg--) {
		if (new_sum_blkaddr + seg * blocks_per_seg < expand_sum_blkaddr) {
			ret = dev_read(ssa, (old_offset_blkaddr + seg * blocks_per_seg) * F2FS_BLKSIZE, seg_size);
			ASSERT(ret >= 0);
		}
		for (blk = blocks_per_seg - 1; blk >= 0; blk--) {
			blkaddr = new_sum_blkaddr + seg * blocks_per_seg + blk;
			if (blkaddr < expand_sum_blkaddr) {
				ret = dev_write_block((char *)ssa + blk * F2FS_BLKSIZE, blkaddr);
				ASSERT(ret >= 0);
			} else {
				ret = dev_write_block(zero_block, blkaddr);
				ASSERT(ret >= 0);
			}
		}
	}

	DBG(0, "Info: Done to migrate SSA blocks: sum_blkaddr = 0x%x -> 0x%x\n",
			old_sum_blkaddr, new_sum_blkaddr);
	free(ssa);
	free(zero_block);
}

static int shrink_nats(struct f2fs_sb_info *sbi,
				struct f2fs_super_block *new_sb)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	block_t old_nat_blkaddr = get_sb(nat_blkaddr);
	unsigned int nat_blocks;
	void *nat_block, *zero_block;
	int nid, ret, new_max_nid;
	pgoff_t block_off;
	pgoff_t block_addr;
	int seg_off;

	nat_block = malloc(BLOCK_SZ);
	ASSERT(nat_block);
	zero_block = calloc(BLOCK_SZ, 1);
	ASSERT(zero_block);

	nat_blocks = get_newsb(segment_count_nat) >> 1;
	nat_blocks = nat_blocks << get_sb(log_blocks_per_seg);
	new_max_nid = NAT_ENTRY_PER_BLOCK * nat_blocks;

	for (nid = nm_i->max_nid - 1; nid > new_max_nid; nid -= NAT_ENTRY_PER_BLOCK) {
		block_off = nid / NAT_ENTRY_PER_BLOCK;
		seg_off = block_off >> sbi->log_blocks_per_seg;
		block_addr = (pgoff_t)(old_nat_blkaddr +
				(seg_off << sbi->log_blocks_per_seg << 1) +
				(block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

		if (f2fs_test_bit(block_off, nm_i->nat_bitmap))
			block_addr += sbi->blocks_per_seg;

		ret = dev_read_block(nat_block, block_addr);
		ASSERT(ret >= 0);

		if (memcmp(zero_block, nat_block, BLOCK_SZ)) {
			ret = -1;
			goto not_avail;
		}
	}
	ret = 0;
	nm_i->max_nid = new_max_nid;
not_avail:
	free(nat_block);
	free(zero_block);
	return ret;
}

static void migrate_nat(struct f2fs_sb_info *sbi,
			struct f2fs_super_block *new_sb)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct f2fs_nm_info *nm_i = NM_I(sbi);
	block_t old_nat_blkaddr = get_sb(nat_blkaddr);
	block_t new_nat_blkaddr = get_newsb(nat_blkaddr);
	unsigned int nat_blocks;
	void *nat_block;
	int nid, ret, new_max_nid;
	pgoff_t block_off;
	pgoff_t block_addr;
	int seg_off;

	nat_block = malloc(BLOCK_SZ);
	ASSERT(nat_block);

	for (nid = nm_i->max_nid - 1; nid >= 0; nid -= NAT_ENTRY_PER_BLOCK) {
		block_off = nid / NAT_ENTRY_PER_BLOCK;
		seg_off = block_off >> sbi->log_blocks_per_seg;
		block_addr = (pgoff_t)(old_nat_blkaddr +
				(seg_off << sbi->log_blocks_per_seg << 1) +
				(block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

		/* move to set #0 */
		if (f2fs_test_bit(block_off, nm_i->nat_bitmap)) {
			block_addr += sbi->blocks_per_seg;
			f2fs_clear_bit(block_off, nm_i->nat_bitmap);
		}

		ret = dev_read_block(nat_block, block_addr);
		ASSERT(ret >= 0);

		block_addr = (pgoff_t)(new_nat_blkaddr +
				(seg_off << sbi->log_blocks_per_seg << 1) +
				(block_off & ((1 << sbi->log_blocks_per_seg) - 1)));

		/* new bitmap should be zeros */
		ret = dev_write_block(nat_block, block_addr);
		ASSERT(ret >= 0);
	}
	/* zero out newly assigned nids */
	memset(nat_block, 0, BLOCK_SZ);
	nat_blocks = get_newsb(segment_count_nat) >> 1;
	nat_blocks = nat_blocks << get_sb(log_blocks_per_seg);
	new_max_nid = NAT_ENTRY_PER_BLOCK * nat_blocks;

	DBG(1, "Write NAT block: %x->%x, max_nid=%x->%x\n",
			old_nat_blkaddr, new_nat_blkaddr,
			get_sb(segment_count_nat),
			get_newsb(segment_count_nat));

	for (nid = nm_i->max_nid; nid < new_max_nid;
				nid += NAT_ENTRY_PER_BLOCK) {
		block_off = nid / NAT_ENTRY_PER_BLOCK;
		seg_off = block_off >> sbi->log_blocks_per_seg;
		block_addr = (pgoff_t)(new_nat_blkaddr +
				(seg_off << sbi->log_blocks_per_seg << 1) +
				(block_off & ((1 << sbi->log_blocks_per_seg) - 1)));
		ret = dev_write_block(nat_block, block_addr);
		ASSERT(ret >= 0);
		DBG(3, "Write NAT: %lx\n", block_addr);
	}
	free(nat_block);
	DBG(0, "Info: Done to migrate NAT blocks: nat_blkaddr = 0x%x -> 0x%x\n",
			old_nat_blkaddr, new_nat_blkaddr);
}

static void migrate_sit(struct f2fs_sb_info *sbi,
		struct f2fs_super_block *new_sb, unsigned int offset)
{
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int ofs = 0, pre_ofs = 0;
	unsigned int segno, index;
	struct f2fs_sit_block *sit_blk = calloc(BLOCK_SZ, 1);
	block_t sit_blks = get_newsb(segment_count_sit) <<
						(sbi->log_blocks_per_seg - 1);
	struct seg_entry *se;
	block_t blk_addr = 0;
	int ret;

	ASSERT(sit_blk);

	/* initialize with zeros */
	for (index = 0; index < sit_blks; index++) {
		ret = dev_write_block(sit_blk, get_newsb(sit_blkaddr) + index);
		ASSERT(ret >= 0);
		DBG(3, "Write zero sit: %x\n", get_newsb(sit_blkaddr) + index);
	}

	for (segno = 0; segno < MAIN_SEGS(sbi); segno++) {
		struct f2fs_sit_entry *sit;

		se = get_seg_entry(sbi, segno);
		if (segno < offset) {
			ASSERT(se->valid_blocks == 0);
			continue;
		}

		ofs = SIT_BLOCK_OFFSET(sit_i, segno - offset);

		if (ofs != pre_ofs) {
			blk_addr = get_newsb(sit_blkaddr) + pre_ofs;
			ret = dev_write_block(sit_blk, blk_addr);
			ASSERT(ret >= 0);
			DBG(1, "Write valid sit: %x\n", blk_addr);

			pre_ofs = ofs;
			memset(sit_blk, 0, BLOCK_SZ);
		}

		sit = &sit_blk->entries[SIT_ENTRY_OFFSET(sit_i, segno - offset)];
		memcpy(sit->valid_map, se->cur_valid_map, SIT_VBLOCK_MAP_SIZE);
		sit->vblocks = cpu_to_le16((se->type << SIT_VBLOCKS_SHIFT) |
							se->valid_blocks);
	}
	blk_addr = get_newsb(sit_blkaddr) + ofs;
	ret = dev_write_block(sit_blk, blk_addr);
	DBG(1, "Write valid sit: %x\n", blk_addr);
	ASSERT(ret >= 0);

	free(sit_blk);
	DBG(0, "Info: Done to restore new SIT blocks: 0x%x\n",
					get_newsb(sit_blkaddr));
}

static void rebuild_checkpoint(struct f2fs_sb_info *sbi,
			struct f2fs_super_block *new_sb, unsigned int offset)
{
	struct f2fs_checkpoint *cp = F2FS_CKPT(sbi);
	unsigned long long cp_ver = get_cp(checkpoint_ver);
	struct f2fs_checkpoint *new_cp;
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	unsigned int free_segment_count, new_segment_count;
	block_t new_cp_blks = 1 + get_newsb(cp_payload);
	block_t orphan_blks = 0;
	block_t new_cp_blk_no, old_cp_blk_no;
	uint32_t crc = 0;
	u32 flags;
	void *buf;
	int i, ret;

	new_cp = calloc(new_cp_blks * BLOCK_SZ, 1);
	ASSERT(new_cp);

	buf = malloc(BLOCK_SZ);
	ASSERT(buf);

	/* ovp / free segments */
	set_cp(rsvd_segment_count, c.new_reserved_segments);
	set_cp(overprov_segment_count, (get_newsb(segment_count_main) -
			get_cp(rsvd_segment_count)) *
			c.new_overprovision / 100);

	/* give 2 sections (DATA and NODE) to trigger GC in advance */
	if (get_cp(overprov_segment_count) < get_cp(rsvd_segment_count))
		set_cp(overprov_segment_count, get_cp(rsvd_segment_count));

	set_cp(overprov_segment_count, get_cp(overprov_segment_count) +
						2 * get_sb(segs_per_sec));

	DBG(0, "Info: Overprovision ratio = %.3lf%%\n", c.new_overprovision);
	DBG(0, "Info: Overprovision segments = %u (GC reserved = %u)\n",
					get_cp(overprov_segment_count),
					c.new_reserved_segments);

	free_segment_count = get_free_segments(sbi);
	new_segment_count = get_newsb(segment_count_main) -
					get_sb(segment_count_main);

	set_cp(free_segment_count, free_segment_count + new_segment_count);
	set_cp(user_block_count, ((get_newsb(segment_count_main) -
			get_cp(overprov_segment_count)) * c.blks_per_seg));

	if (is_set_ckpt_flags(cp, CP_ORPHAN_PRESENT_FLAG))
		orphan_blks = __start_sum_addr(sbi) - 1;

	set_cp(cp_pack_start_sum, 1 + get_newsb(cp_payload));
	set_cp(cp_pack_total_block_count, 8 + orphan_blks + get_newsb(cp_payload));

	/* cur->segno - offset */
	for (i = 0; i < NO_CHECK_TYPE; i++) {
		if (i < CURSEG_HOT_NODE) {
			set_cp(cur_data_segno[i],
					CURSEG_I(sbi, i)->segno - offset);
		} else {
			int n = i - CURSEG_HOT_NODE;

			set_cp(cur_node_segno[n],
					CURSEG_I(sbi, i)->segno - offset);
		}
	}

	/* sit / nat ver bitmap bytesize */
	set_cp(sit_ver_bitmap_bytesize,
			((get_newsb(segment_count_sit) / 2) <<
			get_newsb(log_blocks_per_seg)) / 8);
	set_cp(nat_ver_bitmap_bytesize,
			((get_newsb(segment_count_nat) / 2) <<
			get_newsb(log_blocks_per_seg)) / 8);

	/* update nat_bits flag */
	flags = update_nat_bits_flags(new_sb, cp, get_cp(ckpt_flags));
	if (c.large_nat_bitmap)
		flags |= CP_LARGE_NAT_BITMAP_FLAG;

	if (flags & CP_COMPACT_SUM_FLAG)
		flags &= ~CP_COMPACT_SUM_FLAG;
	if (flags & CP_LARGE_NAT_BITMAP_FLAG)
		set_cp(checksum_offset, CP_MIN_CHKSUM_OFFSET);
	else
		set_cp(checksum_offset, CP_CHKSUM_OFFSET);

	set_cp(ckpt_flags, flags);

	memcpy(new_cp, cp, (unsigned char *)cp->sit_nat_version_bitmap -
						(unsigned char *)cp);
	if (c.safe_resize)
		memcpy((void *)new_cp + CP_BITMAP_OFFSET,
			(void *)cp + CP_BITMAP_OFFSET,
			F2FS_BLKSIZE - CP_BITMAP_OFFSET);

	new_cp->checkpoint_ver = cpu_to_le64(cp_ver + 1);

	crc = f2fs_checkpoint_chksum(new_cp);
	*((__le32 *)((unsigned char *)new_cp + get_cp(checksum_offset))) =
							cpu_to_le32(crc);

	/* Write a new checkpoint in the other set */
	new_cp_blk_no = old_cp_blk_no = get_sb(cp_blkaddr);
	if (sbi->cur_cp == 2)
		old_cp_blk_no += 1 << get_sb(log_blocks_per_seg);
	else
		new_cp_blk_no += 1 << get_sb(log_blocks_per_seg);

	/* write first cp */
	ret = dev_write_block(new_cp, new_cp_blk_no++);
	ASSERT(ret >= 0);

	memset(buf, 0, BLOCK_SZ);
	for (i = 0; i < get_newsb(cp_payload); i++) {
		ret = dev_write_block(buf, new_cp_blk_no++);
		ASSERT(ret >= 0);
	}

	for (i = 0; i < orphan_blks; i++) {
		block_t orphan_blk_no = old_cp_blk_no + 1 + get_sb(cp_payload);

		ret = dev_read_block(buf, orphan_blk_no++);
		ASSERT(ret >= 0);

		ret = dev_write_block(buf, new_cp_blk_no++);
		ASSERT(ret >= 0);
	}

	/* update summary blocks having nullified journal entries */
	for (i = 0; i < NO_CHECK_TYPE; i++) {
		struct curseg_info *curseg = CURSEG_I(sbi, i);

		ret = dev_write_block(curseg->sum_blk, new_cp_blk_no++);
		ASSERT(ret >= 0);
	}

	/* Write nat bits */
	if (flags & CP_NAT_BITS_FLAG)
		write_nat_bits(sbi, new_sb, new_cp, sbi->cur_cp == 1 ? 2 : 1);

	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	/* write the last cp */
	ret = dev_write_block(new_cp, new_cp_blk_no++);
	ASSERT(ret >= 0);

	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	/* disable old checkpoint */
	memset(buf, 0, BLOCK_SZ);
	ret = dev_write_block(buf, old_cp_blk_no);
	ASSERT(ret >= 0);

	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	free(buf);
	free(new_cp);
	DBG(0, "Info: Done to rebuild checkpoint blocks\n");
}

static int backup_meta(struct f2fs_sb_info *sbi, u64 new_end_blkaddr)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	unsigned int segment0_blkaddr = get_sb(segment0_blkaddr);
	unsigned int target_seg = SEG_ALIGN(get_sb(main_blkaddr) - segment0_blkaddr);
	u64 end_blkaddr = get_sb(block_count);
	int blocks_per_seg = 1 << get_sb(log_blocks_per_seg);
	int seg_size = F2FS_BLKSIZE * blocks_per_seg;
	void *buf;
	int i, ret = 0;

	if (get_sb(resize_state) == F2FS_META_BACKUP)
		return ret;
	if ((end_blkaddr + target_seg * blocks_per_seg) > new_end_blkaddr) {
		MSG(0, "\tError: Not enough space for backup metadata\n");
		ret = -1;
		return ret;
	}

	buf = calloc(BLOCK_SZ, blocks_per_seg);
	ASSERT(buf);

	/* Backup CP, SIT, NAT, SSA */
	for (i = 0; i < target_seg; i++) {
		ret = dev_read(buf, (segment0_blkaddr * F2FS_BLKSIZE) + (i * seg_size), seg_size);
		ASSERT(ret >= 0);
		ret = dev_write(buf, ((end_blkaddr + 2) * F2FS_BLKSIZE) + (i * seg_size), seg_size);
		ASSERT(ret >= 0);
	}
	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	set_sb(backupmeta_blkaddr, end_blkaddr);
	set_sb(segment_count_backupmeta, target_seg);
	set_sb(resize_state, F2FS_META_BACKUP);

	/* Backup SB */
	for (i = 0; i < 2; i++) {
		ret = dev_read_block(buf, i);
		ASSERT(ret >= 0);
		memcpy(buf + F2FS_SUPER_OFFSET, sb, sizeof(*sb));
		ret = dev_write_block(buf, end_blkaddr + i);
		ASSERT(ret >= 0);
	}
	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	for (i = 0; i < 2; i++) {
		ret = dev_read_block(buf, i);
		ASSERT(ret >= 0);
		memcpy(buf + F2FS_SUPER_OFFSET, sb, sizeof(*sb));
		ret = dev_write_block(buf, i);
		ASSERT(ret >= 0);
	}
	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	free(buf);
	return ret;
}

static void clear_backup_meta(struct f2fs_sb_info *sbi, struct f2fs_super_block *new_sb)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	unsigned int target_seg = SEG_ALIGN(get_sb(main_blkaddr) - get_sb(segment0_blkaddr));
	u64 end_blkaddr = get_sb(block_count);
	int blocks_per_seg = 1 << get_sb(log_blocks_per_seg);
	int seg_size = F2FS_BLKSIZE * blocks_per_seg;
	void *buf;
	int i, ret;

	buf = calloc(BLOCK_SZ, blocks_per_seg);
	ASSERT(buf);

	set_newsb(backupmeta_blkaddr, 0);
	set_newsb(segment_count_backupmeta, 0);
	set_newsb(resize_state, 0);

	for (i = 0; i < 2; i++) {
		ret = dev_read_block(buf, i);
		ASSERT(ret >= 0);
		memcpy(buf + F2FS_SUPER_OFFSET, new_sb, sizeof(*new_sb));
		ret = dev_write_block(buf, i);
		ASSERT(ret >= 0);
	}
	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	memset(buf, 0, BLOCK_SZ);
	for (i = 0; i < 2; i++) {
		ret = dev_write_block(buf, end_blkaddr + i);
		ASSERT(ret >= 0);
	}
	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	for (i = 0; i < target_seg; i++) {
		ret = dev_write(buf, ((end_blkaddr + 2) * F2FS_BLKSIZE) + (i * seg_size), seg_size);
		ASSERT(ret >= 0);
	}

	ret = f2fs_fsync_device();
	ASSERT(ret >= 0);

	free(buf);
}

void clear_garbage_meta(struct f2fs_sb_info *sbi, struct f2fs_super_block *new_sb)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	unsigned int new_main_blkaddr = get_newsb(main_blkaddr);
	void *zero_block;
	block_t blkaddr = get_sb(main_blkaddr);
	int ret;

	DBG(1, "Info: Found backup metadata. Clear previous garbage meta\n");

	zero_block = calloc(BLOCK_SZ, 1);
	ASSERT(zero_block);

	while (blkaddr < new_main_blkaddr) {
		ret = dev_write_block(zero_block, blkaddr++);
		ASSERT(ret >= 0);
	}

	free(zero_block);
}

int check_fail_safe_resize(struct f2fs_sb_info *sbi, struct f2fs_super_block *new_sb)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct sit_info *sit_i = SIT_I(sbi);
	unsigned int target_segno = SEG_ALIGN(get_newsb(main_blkaddr) -
							get_sb(main_blkaddr));
	int i;

	for (i = 0; i < target_segno; i++) {
		struct seg_entry *se = &sit_i->sentries[i];
		if (se->valid_blocks)
			return -1;
	}

	DBG(1, "Info: pass to checking fail-safe resize\n");
	return 0;
}

static int f2fs_resize_check(struct f2fs_sb_info *sbi, struct f2fs_super_block *new_sb)
{
	struct f2fs_checkpoint *cp = F2FS_CKPT(sbi);
	block_t user_block_count;
	unsigned int overprov_segment_count;

	overprov_segment_count = (get_newsb(segment_count_main) -
			c.new_reserved_segments) *
			c.new_overprovision / 100;

	overprov_segment_count += 2 * get_newsb(segs_per_sec);

	user_block_count = (get_newsb(segment_count_main) -
			overprov_segment_count) * c.blks_per_seg;

	if (get_cp(valid_block_count) > user_block_count)
		return -1;

	return 0;
}

static int f2fs_resize_grow(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct f2fs_super_block new_sb_raw;
	struct f2fs_super_block *new_sb = &new_sb_raw;
	block_t end_blkaddr, old_main_blkaddr, new_main_blkaddr;
	unsigned int offset;
	unsigned int offset_seg = 0;
	int err = -1;

	/* flush NAT/SIT journal entries */
	flush_journal_entries(sbi);

	memcpy(new_sb, F2FS_RAW_SUPER(sbi), sizeof(*new_sb));
	if (get_new_sb(new_sb))
		return -1;

	if (f2fs_resize_check(sbi, new_sb) < 0)
		return -1;

	/* check nat availability */
	if (get_sb(segment_count_nat) > get_newsb(segment_count_nat)) {
		err = shrink_nats(sbi, new_sb);
		if (err) {
			MSG(0, "\tError: Failed to shrink NATs\n");
			return err;
		}
	}

	/* check fail-safe resize availability */
	if (c.fail_safe_resize) {
		if (get_sb(resize_state) & F2FS_META_BACKUP) {
			clear_garbage_meta(sbi, new_sb);
		} else if (check_fail_safe_resize(sbi, new_sb)) {
			MSG(0, "Info: Failed to run on fail-safe mode resize. Try to do normal mode\n");
			c.fail_safe_resize = 0;
		}
	}

	old_main_blkaddr = get_sb(main_blkaddr);
	new_main_blkaddr = get_newsb(main_blkaddr);
	offset = new_main_blkaddr - old_main_blkaddr;
	end_blkaddr = (get_sb(segment_count_main) <<
			get_sb(log_blocks_per_seg)) + get_sb(main_blkaddr);

	err = -EAGAIN;
	if (new_main_blkaddr < end_blkaddr) {
		err = f2fs_defragment(sbi, old_main_blkaddr, offset,
						new_main_blkaddr, 0);
		if (!err)
			offset_seg = offset >> get_sb(log_blocks_per_seg);
		MSG(0, "Try to do defragement: %s\n", err ? "Skip": "Done");
	}
	/* move whole data region */
	if (err)
		migrate_main(sbi, offset);

	if (c.fail_safe_resize && backup_meta(sbi, get_newsb(block_count)) < 0) {
		MSG(0, "Info: Try to do normal mode\n");
		c.fail_safe_resize = 0;
	}
	if (!c.fail_safe_resize)
		migrate_ssa(sbi, new_sb, offset_seg);
	else
		migrate_ssa_safe(sbi, new_sb, offset_seg);
	migrate_nat(sbi, new_sb);
	migrate_sit(sbi, new_sb, offset_seg);
	rebuild_checkpoint(sbi, new_sb, offset_seg);
	update_superblock(new_sb, SB_MASK_ALL);
	if (c.fail_safe_resize)
		clear_backup_meta(sbi, new_sb);
	print_raw_sb_info(sb);
	print_raw_sb_info(new_sb);

	return 0;
}

static int f2fs_resize_shrink(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);
	struct f2fs_super_block new_sb_raw;
	struct f2fs_super_block *new_sb = &new_sb_raw;
	block_t old_end_blkaddr, old_main_blkaddr;
	block_t new_end_blkaddr, new_main_blkaddr, tmp_end_blkaddr;
	unsigned int offset;
	int err = -1;

	/* flush NAT/SIT journal entries */
	flush_journal_entries(sbi);

	memcpy(new_sb, F2FS_RAW_SUPER(sbi), sizeof(*new_sb));
	if (get_new_sb(new_sb))
		return -1;

	if (f2fs_resize_check(sbi, new_sb) < 0)
		return -1;

	/* check nat availability */
	if (get_sb(segment_count_nat) > get_newsb(segment_count_nat)) {
		err = shrink_nats(sbi, new_sb);
		if (err) {
			MSG(0, "\tError: Failed to shrink NATs\n");
			return err;
		}
	}

	old_main_blkaddr = get_sb(main_blkaddr);
	new_main_blkaddr = get_newsb(main_blkaddr);
	offset = old_main_blkaddr - new_main_blkaddr;
	old_end_blkaddr = (get_sb(segment_count_main) <<
			get_sb(log_blocks_per_seg)) + get_sb(main_blkaddr);
	new_end_blkaddr = (get_newsb(segment_count_main) <<
			get_newsb(log_blocks_per_seg)) + get_newsb(main_blkaddr);

	tmp_end_blkaddr = new_end_blkaddr + offset;
	err = f2fs_defragment(sbi, tmp_end_blkaddr,
				old_end_blkaddr - tmp_end_blkaddr,
				tmp_end_blkaddr, 1);
	MSG(0, "Try to do defragement: %s\n", err ? "Insufficient Space": "Done");

	if (err) {
		return -ENOSPC;
	}

	update_superblock(new_sb, SB_MASK_ALL);
	rebuild_checkpoint(sbi, new_sb, 0);
	/*if (!c.safe_resize) {
		migrate_sit(sbi, new_sb, offset_seg);
		migrate_nat(sbi, new_sb);
		migrate_ssa(sbi, new_sb, offset_seg);
	}*/

	/* move whole data region */
	//if (err)
	//	migrate_main(sbi, offset);
	print_raw_sb_info(sb);
	print_raw_sb_info(new_sb);

	return 0;
}

int f2fs_resize(struct f2fs_sb_info *sbi)
{
	struct f2fs_super_block *sb = F2FS_RAW_SUPER(sbi);

	/* may different sector size */
	if ((c.target_sectors * c.sector_size >>
			get_sb(log_blocksize)) < get_sb(block_count))
		if (!c.safe_resize) {
			ASSERT_MSG("Nothing to resize, now only supports resizing with safe resize flag\n");
			return -1;
		} else {
			return f2fs_resize_shrink(sbi);
		}
	else if (((c.target_sectors * c.sector_size >>
			get_sb(log_blocksize)) > get_sb(block_count)) ||
			c.force)
		return f2fs_resize_grow(sbi);
	else {
		MSG(0, "Nothing to resize.\n");
		return 0;
	}
}
