#ifndef ZTD_SK_SHARED_H
#define ZTD_SK_SHARED_H

#include <sys/types.h>

#include <ztd_common.h>

#define PROG_SK "ztdSk"

#define INET_SOCK_STATE_PROG_PATH BPF_FS_PATH PROG_(PROG_SK) TRACEPOINT_ "sock_inet_sock_set_state"

#define SK_DATA_RINGBUF_PATH        BPF_FS_PATH MAP_(PROG_SK) "sk_data_ringbuf"

#if USE_RINGBUF
# define DEFINE_SK_TRACEPOINT(the_system, the_event) \
    DEFINE_BPF_PROG_KVER("tracepoint/" #the_system "/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event, KVER(5, 8, 0))
#else
# define DEFINE_SK_TRACEPOINT(the_system, the_event) \
    DEFINE_BPF_PROG("tracepoint/" #the_system "/" #the_event, AID_ROOT, AID_SYSTEM, tp_##the_event)
#endif

#ifndef AF_INET
#define AF_INET    2
#endif
#ifndef AF_INET6
#define AF_INET6   10
#endif

typedef struct sk_data {
    int reserve;
    int event;

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

    tp_base_data_t base_data;
} sk_data_t;

#endif // ZTD_SK_SHARED_H