
#include "bpf_shared.h"
#include <ztd_fs_shared.h>

#define DEBUG 0
#define DEBUG_ENTRY 0
#define KEEP_UNUSED 0

#define TARGET_FILES_MAP_SIZ 10

DEFINE_BPF_MAP_GRW(target_files_map, HASH, uint64_t, target_file_t, TARGET_FILES_MAP_SIZ, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(fs_data_map, HASH, uint64_t, fs_data_t, 4096, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(fs_tracer_map, HASH, uint64_t, fs_tracer_t, 1, AID_SYSTEM);

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(fs_data_ringbuf, fs_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", false,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, false, false, false);
#endif

#if KEEP_UNUSED
#define bpf_read_user_str(dst, size, reg) \
    bpf_probe_read_user_str(dst, size, POINTER_OF_USER_SPACE(reg))

static int (*bpf_probe_read_kernel)(void* dst, int size, const void* safe_ptr) = (void*)BPF_FUNC_probe_read_kernel;

#define bpf_read_kernel(dst, size, reg) \
    bpf_probe_read_kernel(dst, size, (void*)reg)
#endif

typedef unsigned short  umode_t;

struct f2fs_iget_args {
    uint64_t common;    // 8 bytes

    dev_t dev;          // 4 bytes
    ino_t ino;          // 8 bytes
    ino_t pino;         // 8 bytes
    umode_t mode;       // 2 bytes
    loff_t size;        // 8 bytes (signed)
    unsigned int nlink; // 4 bytes
    blkcnt_t blocks;    // 8 bytes
    uint8_t advise;     // 1 bytes
};

struct f2fs_iget_exit_args {
    uint64_t common;    // 8 bytes

    dev_t dev;          // 4 bytes
    ino_t ino;          // 8 bytes
    int ret;            // 4 bytes (signed)
};

struct f2fs_readdir_args {
    uint64_t common;    // 8 bytes

    dev_t dev;          // 4 bytes
    ino_t ino;          // 8 bytes
    loff_t start;       // 8 bytes (signed)
    loff_t end;         // 8 bytes (signed)
    int err;            // 4 bytes (signed)
};

struct f2fs_readpage_args {
    uint64_t common;        // 8 bytes

    dev_t dev;              // 4 bytes
    ino_t ino;              // 8 bytes
    int type;               // 4 bytes (signed)
    int dir;                // 4 bytes (signed)
    unsigned long index;    // 8 bytes
    int dirty;              // 4 bytes (signed)
    int uptodate;           // 4 bytes (signed)
};

struct f2fs_readpages_args {
    uint64_t common;        // 8 bytes

    dev_t dev;              // 4 bytes
    ino_t ino;              // 8 bytes
    unsigned long start;    // 8 bytes
    unsigned int nrpage;    // 4 bytes
};

struct f2fs_unlink_enter_args {
    uint64_t common;    // 8 bytes

    dev_t dev;          // 4 bytes
    ino_t ino;          // 8 bytes --> [!] dir ino
    loff_t size;        // 8 bytes (signed)
    blkcnt_t blocks;    // 8 bytes
    const char *name;   // 8 bytes
};

struct f2fs_unlink_exit_args {
    uint64_t common;    // 8 bytes

    dev_t dev;          // 4 bytes
    ino_t ino;          // 8 bytes
    int ret;            // 4 bytes (signed)
};

// [!] Same with struct f2fs_readpage_args
struct f2fs_writepage_args {
    uint64_t common;        // 8 bytes

    dev_t dev;              // 4 bytes
    ino_t ino;              // 8 bytes
    int type;               // 4 bytes (signed)
    int dir;                // 4 bytes (signed)
    unsigned long index;    // 8 bytes
    int dirty;              // 4 bytes (signed)
    int uptodate;           // 4 bytes (signed)
};

struct f2fs_writepages_args {
    uint64_t common;                    // 8 bytes

    dev_t dev;                          // 4 bytes
    ino_t ino;                          // 8 bytes
    int type;                           // 4 bytes (signed)
    int dir;                            // 4 bytes (signed)
    long nr_to_write;                   // 8 bytes (signed)
    long pages_skipped;                 // 8 bytes (signed)
    loff_t range_start;                 // 8 bytes (signed)
    loff_t range_end;                   // 8 bytes (signed)
    unsigned long writeback_index;      // 8 bytes
    int sync_mode;                      // 4 bytes (signed)
    unsigned char for_kupdate;          // 1 byte
    unsigned char for_background;       // 1 byte
    unsigned char tagged_writepages;    // 1 byte
    unsigned char for_reclaim;          // 1 byte
    unsigned char range_cyclic;         // 1 byte
    unsigned char for_sync;             // 1 byte
};

struct f2fs_dataread_start_args {
    uint64_t common;                    // 8 bytes
    uint32_t reserved_1;                // __data_loc char[] pathbuf;   --> 4 bytes
    uint64_t reserved_2;                // loff_t offset;               --> 8 bytes
    uint32_t reserved_3;                // int bytes;                   --> 4 bytes
    uint64_t reserved_4;                // loff_t i_size;               --> 8 bytes
    uint32_t reserved_5;                // __data_loc char[] cmdline;   --> 4 bytes
    uint32_t reserved_6;                // pid_t pid;                   --> 4 bytes
    ino_t ino;                          // 8 bytes
};

struct f2fs_dataread_end_args {
    uint64_t common;                    // 8 bytes
    ino_t ino;                          // 8 bytes
    uint64_t reserved_1;                // loff_t offset;               --> 8 bytes
    uint32_t reserved_2;                // int bytes;                   --> 4 bytes
};

struct f2fs_datawrite_start_args {
    uint64_t common;                    // 8 bytes
    uint32_t reserved_1;                // __data_loc char[] pathbuf;   --> 4 bytes
    uint64_t reserved_2;                // loff_t offset;               --> 8 bytes
    uint32_t reserved_3;                // int bytes;                   --> 4 bytes
    uint64_t reserved_4;                // loff_t i_size;               --> 8 bytes
    uint32_t reserved_5;                // __data_loc char[] cmdline;   --> 4 bytes
    uint32_t reserved_6;                // pid_t pid;                   --> 4 bytes
    ino_t ino;                          // 8 bytes
};

struct f2fs_datawrite_end_args {
    uint64_t common;                    // 8 bytes
    ino_t ino;                          // 8 bytes
    uint64_t reserved_1;                // loff_t offset;               --> 8 bytes
    uint32_t reserved_2;                // int bytes;                   --> 4 bytes
};

static inline __always_inline void checkInode(int event, ino_t the_ino, ino_t the_pino) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    target_file_t *tg_file = 0;
    fs_tracer_t *fs_tracer = 0;
    uint64_t lk = 0; // Look-up Key

    fs_tracer = bpf_fs_tracer_map_lookup_elem(&lk);
    if (fs_tracer) {
        pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
        if (pid == fs_tracer->pid) {
            return;
        }
    }
#pragma unroll (TARGET_FILES_MAP_SIZ)
    for (int i = 0 ; i < TARGET_FILES_MAP_SIZ; i++) {
        tg_file = bpf_target_files_map_lookup_elem(&lk);
        if (tg_file) {
            if (the_ino == tg_file->ino) {
#if DEBUG
                bpf_printk("[ztd] - Event : %d, Target : %lu --> Hit!!!", event, tg_file->ino);
#endif
#if USE_RINGBUF
                fs_data_t* output = bpf_fs_data_ringbuf_reserve();
                if (output == NULL) return;

                output->event = event;
                output->ino = the_ino;
                output->pino = the_pino;
                output->base_data.event_time = event_time;
                output->base_data.pid_tgid = bpf_get_current_pid_tgid();
                output->base_data.uid_gid = bpf_get_current_uid_gid();
                bpf_get_current_comm(&output->base_data.comm, sizeof(output->base_data.comm));

                bpf_fs_data_ringbuf_submit(output);
#else
                uint64_t key = ((event & 0xFFFFFFFFFFFFFFFF) << 56) | event_time;
                fs_data_t data = {
                    0,
                    event,
                    the_ino,
                    the_pino,
                    {
                        event_time,
                        bpf_get_current_pid_tgid(),
                        bpf_get_current_uid_gid(),
                    }
                };
                bpf_get_current_comm(&data.base_data.comm, sizeof(data.base_data.comm));
                bpf_fs_data_map_update_elem(&key, &data, BPF_ANY);
#endif
                break;
            }
#if DEBUG
            else {
                bpf_printk("[ztd] - Event : %d, Target : %lu", event, tg_file->ino);
            }
#endif
            lk++;
        }
        else {
            break;
        }
    }
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_iget)
(struct f2fs_iget_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_iget :: ino = %lu, pino = %lu", args->ino, args->pino);
#endif
    checkInode(TRACE_EVENT_F2FS_IGET, args->ino, args->pino);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_iget_exit)
(struct f2fs_iget_exit_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_iget_exit :: ino = %lu, ret = %d", args->ino, args->ret);
#endif
    checkInode(TRACE_EVENT_F2FS_IGET_EXIT, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_readdir)
(struct f2fs_readdir_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_readdir :: ino = %lu", args->ino);
#endif
    checkInode(TRACE_EVENT_F2FS_READDIR, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_readpage)
(struct f2fs_readpage_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_readpage :: ino = %lu, type = %d, dir = %d", args->ino, args->type, args->dir);
    bpf_printk("[ztd] f2fs_readpage :: index = %lu, dirty = %d", args->index, args->dirty);
#endif
    checkInode(TRACE_EVENT_F2FS_READPAGE, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_readpages)
(struct f2fs_readpages_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_readpages :: ino = %lu, start = %lu, nrpage = %u", args->ino, args->start, args->nrpage);
#endif
    checkInode(TRACE_EVENT_F2FS_READPAGES, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_unlink_enter)
(struct f2fs_unlink_enter_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_unlink_enter :: dir ino = %lu, size = %lld, name = %s", args->ino, args->size, args->name);
#endif
    checkInode(TRACE_EVENT_F2FS_UNLINK_ENTER, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_unlink_exit)
(struct f2fs_unlink_exit_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_unlink_exit :: ino = %lu, ret = %d", args->ino, args->ret);
#endif
    checkInode(TRACE_EVENT_F2FS_UNLINK_EXIT, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_writepage)
(struct f2fs_writepage_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_writepage :: ino = %lu, type = %d, dir = %d", args->ino, args->type, args->dir);
    bpf_printk("[ztd] f2fs_writepage :: index = %lu, dirty = %d", args->index, args->dirty);
#endif
    checkInode(TRACE_EVENT_F2FS_WRITEPAGE, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_writepages)
(struct f2fs_writepages_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_writepages :: ino = %lu, type = %d, dir = %d", args->ino, args->type, args->dir);
    bpf_printk("[ztd] f2fs_writepages :: nr_to_write = %ld, pages_skipped = %ld", args->nr_to_write, args->pages_skipped);
#endif
    checkInode(TRACE_EVENT_F2FS_WRITEPAGES, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_dataread_start)
(struct f2fs_dataread_start_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_dataread_start :: ino = %lu", args->ino);
#endif
    checkInode(TRACE_EVENT_F2FS_DATAREAD_START, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_dataread_end)
(struct f2fs_dataread_end_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_dataread_end :: ino = %lu", args->ino);
#endif
    checkInode(TRACE_EVENT_F2FS_DATAREAD_END, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_datawrite_start)
(struct f2fs_datawrite_start_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_datawrite_start :: ino = %lu", args->ino);
#endif
    checkInode(TRACE_EVENT_F2FS_DATAWRITE_START, args->ino, 0);
    return 1;
}

DEFINE_FS_TRACEPOINT(f2fs, f2fs_datawrite_end)
(struct f2fs_datawrite_end_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] f2fs_datawrite_end :: ino = %lu", args->ino);
#endif
    checkInode(TRACE_EVENT_F2FS_DATAWRITE_END, args->ino, 0);
    return 1;
}

#if KEEP_UNUSED
DEFINE_ZT_KPROBE(do_sys_openat2)
(kp_ctx_t* ctx) {
    uint64_t event_time = bpf_ktime_get_boot_ns();
    target_file_t *tg_file = 0;
    fs_tracer_t *fs_tracer = 0;
    uint64_t lk = 0; // Look-up Key

    fs_tracer = bpf_fs_tracer_map_lookup_elem(&lk);
    if (fs_tracer) {
        pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
        if (pid == fs_tracer->pid) {
            return 0;
        }
    }

    filename_t filename = {};
    bpf_read_user_str(filename.name, sizeof(filename.name), ctx->regs[1]);

    int event = TRACE_EVENT_SYS_OPEN;
#pragma unroll (TARGET_FILES_MAP_SIZ)
    for (int n = 0 ; n < TARGET_FILES_MAP_SIZ; n++) {
        tg_file = bpf_target_files_map_lookup_elem(&lk);
        if (tg_file) {
            for (int i = 0 ; i < 256; i++) {
                if (tg_file->name[i] != filename.name[i]) {
                    break;
                }
                if (tg_file->name[i] == '\0') {
#if DEBUG
                    bpf_printk("[ztd] Event : %d, Target : %lu, Name : %s --> Hit!!!",
                        event, tg_file->ino, filename.name);
#endif
                    uint64_t key = ((event & 0xFFFFFFFFFFFFFFFF) << 56) | event_time;
                    fs_data_t data = {
                        0,
                        event,
                        tg_file->ino,
                        0, /* pino */
                        event_time,
                        bpf_get_current_pid_tgid(),
                        bpf_get_current_uid_gid()
                    };
                    bpf_fs_data_map_update_elem(&key, &data, BPF_ANY);
                    return 0;
                }
            }
            lk++;
        }
        else {
            break;
        }
    }

    return 0;
}

DEFINE_ZT_KPROBE(do_filp_open)
(kp_ctx_t* ctx) {
    fs_tracer_t *fs_tracer = 0;
    uint64_t lk = 0; // Look-up Key
    fake_filename_t ffn= {};

    fs_tracer = bpf_fs_tracer_map_lookup_elem(&lk);
    if (fs_tracer) {
        pid_t pid = (pid_t)(bpf_get_current_pid_tgid() >> 32);
        if (pid == fs_tracer->pid) {
            return 0;
        }
    }

    bpf_read_kernel(&ffn, sizeof(ffn), ctx->regs[1]);
    bpf_printk("[ztd] do_filp_open() - filename: %s", ffn.name);
    return 0;
}
#endif

LICENSE("GPL");