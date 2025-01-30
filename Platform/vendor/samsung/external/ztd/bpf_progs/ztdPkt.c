#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "bpf_shared.h"
#include <ztd_pkt_shared.h>

#define DEBUG_ENTRY 0

#define IP_ETH_OFFSET_SRC   (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_ETH_OFFSET_DST   (ETH_HLEN + offsetof(struct iphdr, daddr))
#define TCP4_DPORT_OFFSET   (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP4_SPORT_OFFSET   (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, source))

#define TLS_DATA_OFFSET      0x42
#define TLS_HELLO_MESSAGE_ID 0x16
#define TLS_CLIENT_HELLO_ID  0x01
#define TLS_SERVER_HELLO_ID  0x02

#define TLS_HEADER_LEN  6
#define TLS_MESSAGE_TYPE_OFFSET         0x00
#define TLS_HELLO_MESSAGE_TYPE_OFFSET   0x05

#define PKT_SEGMENT_SIZE_1   1
#define PKT_SEGMENT_SIZE_2   2
#define PKT_SEGMENT_SIZE_3   3
#define PKT_SEGMENT_SIZE_4   4
#define BYTES_PER_SEGMENT    PKT_SEGMENT_SIZE_4
#define MAX_PKT_SEGMENTS     HELLO_DATA_LEN/BYTES_PER_SEGMENT

static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to, int len) = (void*)BPF_FUNC_skb_load_bytes;
static uint32_t(*bpf_get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;

#if USE_RINGBUF
DEFINE_BPF_RINGBUF_EXT(tls_pkt_ringbuf, tls_pkt_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", false,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, false, false, false);
DEFINE_BPF_MAP_GRW(tls_pkt_map, PERCPU_ARRAY, uint32_t, tls_pkt_t, 1, AID_SYSTEM);
#endif

static inline __always_inline void copy_tls_hello_data(struct __sk_buff* skb, tls_pkt_t* output) {
    uint8_t* pcursor = (uint8_t*)output->hello_data;
    int offset = 0;

    //TODO: find a way to optimize data copy.
    //      as of now, bpf only provides bpf_skb_load_bytes() for reading skb bytes
    //      and bpf restricts its usage by forcing a constant value as data size for loading bytes.
    //      the bpf verifier does not allow passing a variable as data size to bpf_skb_load_bytes()
    for (int i = 0; i < MAX_PKT_SEGMENTS; i++) {
        offset = i * BYTES_PER_SEGMENT;
        pcursor = (uint8_t*)(output->hello_data + offset);
        if (bpf_skb_load_bytes(skb, TLS_DATA_OFFSET + offset, pcursor, PKT_SEGMENT_SIZE_4) == 0) {
            output->data_len += PKT_SEGMENT_SIZE_4;
        }
        else if (bpf_skb_load_bytes(skb, TLS_DATA_OFFSET + offset, pcursor, PKT_SEGMENT_SIZE_3) == 0) {
            output->data_len += PKT_SEGMENT_SIZE_3;
        }
        else if (bpf_skb_load_bytes(skb, TLS_DATA_OFFSET + offset, pcursor, PKT_SEGMENT_SIZE_2) == 0) {
            output->data_len += PKT_SEGMENT_SIZE_2;
        }
        else if (bpf_skb_load_bytes(skb, TLS_DATA_OFFSET + offset, pcursor, PKT_SEGMENT_SIZE_1) == 0) {
            output->data_len += PKT_SEGMENT_SIZE_1;
        }
        if (TLS_DATA_OFFSET + offset + 1 >= skb->len) {
            break;
        }
    }
}

static inline __always_inline bool is_tls_packet(struct __sk_buff* skb, uint8_t direction) {

    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;
    struct ethhdr* eth = data;
    struct iphdr* ip = (void*)(eth + 1);
    struct tcphdr* tcph = (void*)(ip + 1);

    if (((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)
        || (eth->h_proto != htons(ETH_P_IP)) || (ip->protocol != IPPROTO_TCP)
        || (tcph->syn || tcph->fin || tcph->rst))
        return false;

    uint8_t tlshdr[TLS_HEADER_LEN];
    bpf_skb_load_bytes(skb, TLS_DATA_OFFSET, &tlshdr, sizeof(tlshdr));
    if ((tlshdr[TLS_MESSAGE_TYPE_OFFSET] != TLS_HELLO_MESSAGE_ID)
        || (direction == NET_EGRESS && tlshdr[TLS_HELLO_MESSAGE_TYPE_OFFSET] != TLS_CLIENT_HELLO_ID)
        || (direction == NET_INGRESS && tlshdr[TLS_HELLO_MESSAGE_TYPE_OFFSET] != TLS_SERVER_HELLO_ID))
        return false;

    return true;
}

static inline __always_inline int extract_tls_hello_packet(struct __sk_buff* skb, uint8_t direction) {

#if USE_RINGBUF
    if (skb->protocol != htons(ETH_P_IP) || !is_tls_packet(skb, direction))
        return TC_ACT_UNSPEC;

    uint32_t zero = 0;
    tls_pkt_t* output = bpf_tls_pkt_map_lookup_elem(&zero);
    if (output != NULL) {
        output->len = skb->len;
        output->uid = bpf_get_socket_uid(skb);
        bpf_skb_load_bytes(skb, IP_ETH_OFFSET_SRC, &output->local_ip4, sizeof(output->local_ip4));
        bpf_skb_load_bytes(skb, IP_ETH_OFFSET_DST, &output->remote_ip4, sizeof(output->remote_ip4));
        output->timestamp = bpf_ktime_get_boot_ns();
        output->remote_port = load_half(skb, TCP4_DPORT_OFFSET);
        output->local_port = load_half(skb, TCP4_SPORT_OFFSET);
        output->type = direction;
        output->data_len = 0;

        copy_tls_hello_data(skb, output);
        bpf_tls_pkt_ringbuf_output(output);
    }
#endif
    return TC_ACT_UNSPEC;
}

DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/tls_pkt", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_tls_pkt)
(struct __sk_buff* skb) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] schedcls/ingress/tls_pkt");
#endif
    return extract_tls_hello_packet(skb, NET_INGRESS);
}

DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/tls_pkt", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_tls_pkt)
(struct __sk_buff* skb) {
#if DEBUG_ENTRY
    bpf_printk("[ztd] schedcls/egress/tls_pkt");
#endif
    return extract_tls_hello_packet(skb, NET_EGRESS);
}

LICENSE("GPL");