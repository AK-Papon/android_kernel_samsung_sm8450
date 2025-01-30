
#include "bpf_shared.h"
#include <ztd_sk_shared.h>

#define DEBUG_ENTRY 0

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(sk_data_ringbuf, sk_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", false,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, false, false, false);
#endif

struct inet_sock_state_args {
    uint64_t common;                // 8 bytes
    const void* skaddr;
    int oldstate;
    int newstate;
    uint16_t sport;
    uint16_t dport;
    uint16_t family;
    uint16_t protocol;
    uint8_t saddr[4];
    uint8_t daddr[4];
    uint8_t saddr_v6[16];
    uint8_t daddr_v6[16];
};

static inline __always_inline void checkSocket(int event, struct inet_sock_state_args *args) {
    uint64_t event_time = bpf_ktime_get_boot_ns();

#if USE_RINGBUF
    sk_data_t* output = bpf_sk_data_ringbuf_reserve();
    if (output == NULL) return;

    output->oldstate = args->oldstate;
    output->newstate = args->newstate;
    output->sport = args->sport;
    output->dport = args->dport;
    output->family = args->family;
    output->protocol = args->protocol;

    if (args->family == AF_INET) { // AF_INET(2)
        __builtin_memcpy(&output->saddr, args->saddr, sizeof(output->saddr));
        __builtin_memcpy(&output->daddr, args->daddr, sizeof(output->daddr));
    } else {                       // AF_INET6(10)
        __builtin_memcpy(&output->saddr_v6, args->saddr_v6, sizeof(output->saddr_v6));
        __builtin_memcpy(&output->daddr_v6, args->daddr_v6, sizeof(output->daddr_v6));
    }

    output->event = event;
    output->base_data.event_time = event_time;
    output->base_data.pid_tgid = bpf_get_current_pid_tgid();
    output->base_data.uid_gid = bpf_get_current_uid_gid();
    bpf_get_current_comm(&output->base_data.comm, sizeof(output->base_data.comm));

    bpf_sk_data_ringbuf_submit(output);
#endif
}

DEFINE_SK_TRACEPOINT(sock, inet_sock_set_state)
(struct inet_sock_state_args *args) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] inet_sock_set_state :: family = %u", args->family);
#endif
    checkSocket(TRACE_EVENT_INET_SOCK_SET_STATE, args);
    return 1;
}

LICENSE("GPL");