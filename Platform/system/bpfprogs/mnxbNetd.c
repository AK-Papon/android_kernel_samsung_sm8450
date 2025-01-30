#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include "bpf_helpers.h"
#include "include/mnxbBpfShared.h"

#include <linux/pkt_cls.h>
#include <linux/filter.h>

// bionic kernel uapi linux/udp.h header is munged...
#define __kernel_udphdr udphdr
#include <linux/udp.h>

#define BPF_PASS 1
#define BPF_DROP 0
#define TCP_ACK 16
#define DEFAULT_ADV_WINDOW 1024
#define QUIC_PORT 443

// This is used for xt_bpf program only.
#define BPF_NOMATCH 0
#define BPF_MATCH 1

#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)
#define IPPROTO_IHL_OFF 0
#define TCP_FLAG_OFF 13
#define RST_OFFSET 2


//MNXB : start
#define IP_OFF_SRC   (offsetof(struct iphdr, saddr))
#define IP_OFF_DST   (offsetof(struct iphdr, daddr))

static int (*bpf_skb_load_bytes)(struct __sk_buff *skb, int off, void *to,
                                int len) = (void *) BPF_FUNC_skb_load_bytes;

static uint32_t (*bpf_get_socket_uid)(struct __sk_buff *skb) = (void *)BPF_FUNC_get_socket_uid;

static int (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset, __u64 from, __u64 to,
                                __u64 flags) = (void *) BPF_FUNC_l4_csum_replace;

static int (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset, const void *from, __u32 len,
                                __u64 flags) = (void *) BPF_FUNC_skb_store_bytes;

// For Mobile data
#define IP_ETH_OFF_SRC   (IP_OFF_SRC)
#define IP_ETH_OFF_DST   (IP_OFF_DST)

#define IP_HDR_PROTOCOL  (offsetof(struct iphdr, protocol))
#define IP_HDR_LENGTH    (sizeof(struct iphdr))

#define IPV6_HDR_PROTOCOL (offsetof(struct ipv6hdr, nexthdr))
#define IPV6_HDR_LENGTH   (sizeof(struct ipv6hdr))

#define TCP_DPORT_OFF     offsetof(struct tcphdr, dest)
#define TCP_SPORT_OFF     offsetof(struct tcphdr, source)

#define UDP_DPORT_OFF     offsetof(struct udphdr, dest)
#define UDP_SPORT_OFF     offsetof(struct udphdr, source)

#define TCP_OFF_CSUM      offsetof(struct tcphdr, check)

// Android only supports little endian architectures
#define htons(x) (__builtin_constant_p(x) ? ___constant_swab16(x) : __builtin_bswap16(x))
#define htonl(x) (__builtin_constant_p(x) ? ___constant_swab32(x) : __builtin_bswap32(x))
#define ntohs(x) htons(x)
#define ntohl(x) htonl(x)

#define IP_V4_NW htons(ETH_P_IP)
#define IP_V6_NW htons(ETH_P_IPV6)
//#define DNS_PORT htons(53)

#define MNXB_UID_DEST_MAP_SIZE 1024
#define MNXB_ADV_WINDOW_MAP_SIZE 2
#define MNXB_L4_STATS_MAP_SIZE 8

#define DIRECTION_INGRESS 0
#define DIRECTION_EGRESS 1

// Maps for determining the priority applications
DEFINE_BPF_MAP(mnxb_uid_owner_map, HASH, uint32_t, MnxbUidOwnerValue, MNXB_UID_OWNER_MAP_SIZE)
DEFINE_BPF_MAP(mnxb_uid_dest6_map, HASH, uint16_t, uint8_t, MNXB_UID_OWNER_MAP_SIZE)
DEFINE_BPF_MAP(mnxb_adv_window_map, HASH, uint8_t, uint16_t, MNXB_ADV_WINDOW_MAP_SIZE)
DEFINE_BPF_MAP(mnxb_l4_stats_map, HASH, uint8_t, int64_t, MNXB_L4_STATS_MAP_SIZE)

static inline bool mnxb_is_uid_allowed(struct __sk_buff *skb) {

    uint32_t sock_uid = bpf_get_socket_uid(skb);
    //if (is_system_uid(sock_uid)) return BPF_MATCH;

    MnxbUidOwnerValue *mnxbMatch = bpf_mnxb_uid_owner_map_lookup_elem(&sock_uid);
    if (mnxbMatch) {
        return mnxbMatch->rule & MNXB_BPF_MATCH;
    }

    return BPF_NOMATCH;
}

static inline void mnxb_mark_uid_dest6_map(__u16 key) {
    __u8 mark = 1;

    bpf_mnxb_uid_dest6_map_update_elem(&key, &mark, 0);
}

static inline void count_l4_stats(struct __sk_buff *skb, uint8_t l4Proto, uint8_t direction) {
    if (l4Proto == IPPROTO_TCP || l4Proto == IPPROTO_UDP) {
        uint8_t key = (l4Proto * 10) + direction;
        int64_t *value = bpf_mnxb_l4_stats_map_lookup_elem(&key);
        if (value) {
            __sync_fetch_and_add(value, skb->len);
            bpf_mnxb_l4_stats_map_update_elem(&key, value, 0);
        } else {
            int64_t firstLen = (int64_t) skb->len;
            bpf_mnxb_l4_stats_map_update_elem(&key, &firstLen, 0);
        }
    }
}

//SEC("schedcls/ingress/mnxb_ether")
DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/mnxb_ether", AID_ROOT, AID_SYSTEM, sched_cls_ingress_mnxb_ether)
(struct __sk_buff *skb) {
    int ret = 0;
    uint8_t proto = 0;
    uint16_t port = 0;
    uint8_t offset = IP_HDR_LENGTH;
    __u8 *mark = 0;

    // Fetch the port when the mnxb is disabled or the MCP is enabled
    if (skb->protocol == IP_V4_NW) {
        ret = bpf_skb_load_bytes(skb, IP_HDR_PROTOCOL, &proto, 1);
    } else if (skb->protocol == IP_V6_NW) {
        ret = bpf_skb_load_bytes(skb, IPV6_HDR_PROTOCOL, &proto, 1);
        offset = IPV6_HDR_LENGTH;
    }

    // Now fetch the port
    if (!ret) {
        if (proto == IPPROTO_TCP) {
            ret = bpf_skb_load_bytes(skb, offset + TCP_DPORT_OFF, &port, 2);
        } else if (proto == IPPROTO_UDP) {
            // Since QUIC's retransmission cannot be prevented, so returning OK
            ret = bpf_skb_load_bytes(skb, offset + UDP_DPORT_OFF, &port, 2);
        }
        if (ret != 0) {
            return TC_ACT_UNSPEC;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    // Fetch the mark value
    if (!ret && port != 0) {
        mark = bpf_mnxb_uid_dest6_map_lookup_elem(&port);
    }
    if (mark && *mark == 1) {
        return TC_ACT_OK;
    } else {
        // Store the values to the non priority map
        count_l4_stats(skb, proto, DIRECTION_INGRESS);
        if (proto == IPPROTO_UDP) {
            return TC_ACT_OK;
        }
    }

    uint8_t adv_window_index = ADV_WINDOW_WRITE_INDEX;
    uint16_t *window = bpf_mnxb_adv_window_map_lookup_elem(&adv_window_index);
    uint16_t windowSize = 0;
    if (window && *window) {
        windowSize = *window;
    }

    if (windowSize != 0 && proto == IPPROTO_TCP) {
        return TC_ACT_OK;
    }
    return TC_ACT_UNSPEC;
}

//SEC("schedcls/egress/mnxb_ether")
DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/mnxb_ether", AID_ROOT, AID_SYSTEM, sched_cls_egress_mnxb_ether)
(struct __sk_buff *skb) {

    bool is_allowed =  mnxb_is_uid_allowed(skb);
    int ret = -1;
    uint8_t proto = 0;
    uint16_t port = 0;
    uint8_t offset = IP_HDR_LENGTH;

    // Fetch the port when the mnxb is disabled
    if (skb->protocol == IP_V4_NW) {
        ret = bpf_skb_load_bytes(skb, IP_HDR_PROTOCOL, &proto, 1);
    } else if (skb->protocol == IP_V6_NW) {
        ret = bpf_skb_load_bytes(skb, IPV6_HDR_PROTOCOL, &proto, 1);
        offset = IPV6_HDR_LENGTH;
    }

    // Now fetch the port
    if (!ret) {
        if (proto == IPPROTO_TCP) {
            ret = bpf_skb_load_bytes(skb, offset + TCP_SPORT_OFF, &port, 2);
        } else if (proto == IPPROTO_UDP) {
            // Since QUIC's retransmission cannot be prevented, so returning OK
            ret = bpf_skb_load_bytes(skb, offset + UDP_SPORT_OFF, &port, 2);
        }
        if (ret != 0) {
            return TC_ACT_UNSPEC;
        }
    } else {
        return TC_ACT_UNSPEC;
    }

    // for debugging purpose
    if (is_allowed) {
        if (!ret && port != 0) {
            // To return from here when MNXB is not enabled and is allowed
            // Mark for priority irrespective of IPV4 or IPv6
            mnxb_mark_uid_dest6_map(port);
            return TC_ACT_OK;
        }
    } else {
        // Store the values to the non priority map
        count_l4_stats(skb, proto, DIRECTION_EGRESS);
        if (proto == IPPROTO_UDP) {
            return TC_ACT_OK;
        }
    }

    if (proto == IPPROTO_TCP) {
        uint8_t adv_window_index = ADV_WINDOW_WRITE_INDEX;
        uint16_t *window = bpf_mnxb_adv_window_map_lookup_elem(&adv_window_index);
        uint16_t windowSize = 0;
        if (window && *window) {
            windowSize = *window;
        }

        if (windowSize > 0) {
            uint8_t flag;
            ret = bpf_skb_load_bytes(skb, offset + TCP_FLAG_OFF, &flag, 1);

            if (ret == 0 && (flag & TCP_ACK)) {
                uint16_t adv_window = DEFAULT_ADV_WINDOW;
                ret = bpf_skb_load_bytes(skb, offset + TCP_FLAG_OFF + 1, &adv_window, 2);
                if (ret == 0) {
                    uint16_t org_adv_window = adv_window;
                    adv_window = ntohs(adv_window);
                    // update the adv window
                    uint16_t stored_adv_window = (uint16_t) windowSize;
                    if (stored_adv_window >= 0 && stored_adv_window < adv_window) {
                        uint16_t new_window = htons(stored_adv_window);
                        ret = bpf_l4_csum_replace(skb, offset + TCP_OFF_CSUM, org_adv_window, new_window, sizeof(new_window));
                        if (ret == 0) {
                            ret = bpf_skb_store_bytes(skb, offset + TCP_FLAG_OFF + 1, &new_window, sizeof(new_window), 0);
                            if (ret == 0) return TC_ACT_OK;
                        }
                    }
                }
            }
        }
    }
    return TC_ACT_UNSPEC;
}
// Once logging is not required then convert from GPL to "Apache 2.0" license
LICENSE("Apache 2.0");
CRITICAL("sem netd mnxb");