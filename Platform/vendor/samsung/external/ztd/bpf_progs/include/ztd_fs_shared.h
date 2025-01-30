#ifndef ZTD_FS_SHARED_H
#define ZTD_FS_SHARED_H

#include <sys/types.h>

#include <ztd_common.h>

#define PROG_FS "ztdFs"

#define F2FS_IGET_PROG_PATH         BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_iget"
#define F2FS_IGET_EXIT_PROG_PATH    BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_iget_exit"
#define F2FS_READDIR_PROG_PATH      BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_readdir"
#define F2FS_READPAGE_PROG_PATH     BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_readpage"
#define F2FS_READPAGES_PROG_PATH    BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_readpages"
#define F2FS_UNLINK_ENTER_PROG_PATH BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_unlink_enter"
#define F2FS_UNLINK_EXIT_PROG_PATH  BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_unlink_exit"
#define F2FS_WRITEPAGE_PROG_PATH    BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_writepage"
#define F2FS_WRITEPAGES_PROG_PATH   BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_writepage"

#define F2FS_DATAREAD_START_PROG_PATH   BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_dataread_start"
#define F2FS_DATAREAD_END_PROG_PATH     BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_dataread_end"
#define F2FS_DATAWRITE_START_PROG_PATH  BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_datawrite_start"
#define F2FS_DATAWRITE_END_PROG_PATH    BPF_FS_PATH PROG_(PROG_FS) TRACEPOINT_ "f2fs_f2fs_datawrite_end"

#define TARGET_FILES_MAP_PATH       BPF_FS_PATH MAP_(PROG_FS) "target_files_map"
#define FS_DATA_MAP_PATH            BPF_FS_PATH MAP_(PROG_FS) "fs_data_map"
#define FS_TRACER_MAP_PATH          BPF_FS_PATH MAP_(PROG_FS) "fs_tracer_map"

#define FS_DATA_RINGBUF_PATH        BPF_FS_PATH MAP_(PROG_FS) "fs_data_ringbuf"

#define FS_KPROBE_PROG              BPF_FS_PATH PROG_(PROG_FS) KPROBE_

#if USE_RINGBUF
# define DEFINE_FS_TRACEPOINT(the_system, the_event) \
    DEFINE_BPF_PROG_KVER("tracepoint/" #the_system "/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event, KVER(5, 8, 0))
#else
# define DEFINE_FS_TRACEPOINT(the_system, the_event) \
    DEFINE_BPF_PROG("tracepoint/" #the_system "/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event)
#endif

typedef struct fs_tracer {
    pid_t pid; // (idx:0)
} fs_tracer_t;

typedef struct target_file {
    char name[256];
    uint64_t ino;
} target_file_t;

typedef struct fs_data {
    int reserve;
    int event;
    uint64_t ino;
    uint64_t pino;

    tp_base_data_t base_data;
} fs_data_t;

typedef struct filename {
    char name[256];
} filename_t;

/*
 * Originated from struct filename in include/linux/fs.h
 */
typedef struct fake_filename {
    const char          *name;  /* pointer to actual string */
//  const __user char   *uptr;  /* original userland pointer */
//  int	                refcnt;
//  struct audit_names  *aname;
//  const char          iname[];
} fake_filename_t;

typedef struct kp_ctx {
    uint64_t regs[31];
} kp_ctx_t;

#endif // ZTD_FS_SHARED_H
