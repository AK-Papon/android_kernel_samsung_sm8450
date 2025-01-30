
#include "bpf_shared.h"
#include <ztd_sc_shared.h>

#define DEBUG_ENTRY 0

DEFINE_BPF_MAP_GRW(sc_mount_data_map, HASH, uint64_t, sc_mount_data_t, 128, AID_SYSTEM);

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(sc_data_ringbuf, sc_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", true,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, false, false, false);
#endif

static inline __always_inline void onSyscallMountEnter(sys_enter_data_t *args) {
    sc_mount_data_t data = {};
    data.base_data.event_time = bpf_ktime_get_boot_ns();
    data.base_data.pid_tgid = bpf_get_current_pid_tgid();
    data.base_data.uid_gid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&data.base_data.comm, sizeof(data.base_data.comm));

    bpf_probe_read_user_str(data.dev_name, sizeof(data.dev_name), POINTER_OF_USER_SPACE(args->args[0]));
    bpf_probe_read_user_str(data.dir_name, sizeof(data.dir_name), POINTER_OF_USER_SPACE(args->args[1]));
    bpf_probe_read_user_str(data.type, sizeof(data.type), POINTER_OF_USER_SPACE(args->args[2]));
    data.flags = args->args[3];
    bpf_probe_read_user_str(data.data, sizeof(data.data), POINTER_OF_USER_SPACE(args->args[4]));

    uint64_t key = data.base_data.pid_tgid;
    bpf_sc_mount_data_map_update_elem(&key, &data, BPF_ANY);
}

static inline __always_inline void onSyscallMountExit(sys_exit_data_t *args) {
    uint64_t key = bpf_get_current_pid_tgid();
    sc_mount_data_t *data = bpf_sc_mount_data_map_lookup_elem(&key);

    if (data) {
        data->ret = args->ret;
#ifdef USE_RINGBUF
        sc_data_t *output = bpf_sc_data_ringbuf_reserve();
        if (output == NULL) return;

        output->event = TRACE_EVENT_SYS_MOUNT;
        output->nr = GENERIC_SYSCALL_NR_MOUNT;
        __builtin_memcpy(&output->u.sc_mount.data, data, sizeof(sc_mount_data_t));

        bpf_sc_data_ringbuf_submit(output);
#endif
        bpf_sc_mount_data_map_delete_elem(&key);
    }
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_enter, sc_mount_enter)
(sys_enter_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_MOUNT) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_enter :: NR = %ld", args->id);
#endif
        onSyscallMountEnter(args);
    }
    return 1;
}

DEFINE_SC_TRACEPOINT(raw_syscalls, sys_exit, sc_mount_exit)
(sys_exit_data_t *args) {
    if (args->id == GENERIC_SYSCALL_NR_MOUNT) {
#if DEBUG_ENTRY
        bpf_printk("[ztd] sys_exit :: NR = %ld", args->id);
#endif
        onSyscallMountExit(args);
    }
    return 1;
}

LICENSE("GPL");