#pragma once

#include <sys/types.h>

#include <ztd_common.h>

#define PROG_PKT "ztdPkt"

#define INGRESS_TLS_PKT_PROG_PATH    BPF_FS_PATH PROG_(PROG_PKT)   SCHEDCLS_ "ingress_tls_pkt"
#define EGRESS_TLS_PKT_PROG_PATH     BPF_FS_PATH PROG_(PROG_PKT)   SCHEDCLS_ "egress_tls_pkt"
#define TLS_PKT_RINGBUF_PATH        BPF_FS_PATH MAP_(PROG_PKT)    "tls_pkt_ringbuf"
#define TLS_PKT_MAP_PATH            BPF_FS_PATH MAP_(PROG_PKT)    "tls_pkt_map"

#define NET_INGRESS 1
#define NET_EGRESS  2

#define HELLO_DATA_LEN    1452

typedef struct tls_pkt {
    uint64_t timestamp;
    uint32_t uid;
    uint32_t len;
    uint32_t remote_ip4;
    uint32_t local_ip4;
    uint16_t remote_port;
    uint16_t local_port;
    uint16_t data_len;
    uint16_t hello_len;
    uint8_t type;
    uint8_t hello_data[HELLO_DATA_LEN];
} tls_pkt_t;

#ifdef __cplusplus
#include <string>

typedef struct pkt_data {
    int reserve;
    int event;

    uint64_t event_time;
    uint32_t uid;
    uint32_t type;
    std::string fingerprint;
    std::string saddr;
    std::string daddr;
    uint16_t sport;
    uint16_t dport;
} pkt_data_t;

#endif