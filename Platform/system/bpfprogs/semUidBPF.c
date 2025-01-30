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
#include <netdutils/UidConstants.h>
#include "bpf_helpers.h"
#include <ss_bpf_shared.h>
//APE : start
#include <linux/pkt_cls.h>
#include <linux/filter.h>

// bionic kernel uapi linux/udp.h header is munged...
#define __kernel_udphdr udphdr
#include <linux/udp.h>
//APE : end

// This is used for xt_bpf program only.
#define BPF_NOMATCH 0
#define BPF_MATCH 1

//APE : start
#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)
#define IP_OFF_SRC   (offsetof(struct iphdr, saddr))
#define IP_OFF_DST   (offsetof(struct iphdr, daddr))
#define IP_ETH_OFF_SRC   (ETH_HLEN + IP_OFF_SRC)
#define IP_ETH_OFF_DST   (ETH_HLEN + IP_OFF_DST)

#define TCP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define TCP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))

#define UDP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest))
#define UDP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, source))
// > APE:End

#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
//#endif 

DEFINE_BPF_MAP(oem_uid_owner_map, HASH, uint32_t, OemUidOwnerValue, OEM_UID_OWNER_MAP_SIZE)

// < APE:Start
#define SEMAPE_UID_DEST_MAP_SIZE 2048
DEFINE_BPF_MAP(ape_uid_dest_map, HASH, uint32_t, uint8_t, SEMAPE_UID_DEST_MAP_SIZE)
DEFINE_BPF_MAP(ape_uid_dest6_map, HASH, uint16_t, uint8_t, SEMAPE_UID_DEST_MAP_SIZE)
// > APE:End

#define TRAFFIC_STATS_MAP_SIZE 1024
DEFINE_BPF_MAP(tsm_inter_packet_rx_stats_map, HASH, UidStatsKey, InterPacketRxStatsValue, TRAFFIC_STATS_MAP_SIZE)
DEFINE_BPF_MAP(tsm_inter_packet_tx_stats_map, HASH, UidStatsKey, InterPacketTxStatsValue, TRAFFIC_STATS_MAP_SIZE)
DEFINE_BPF_MAP(tsm_traffic_stats_map, HASH, UidStatsKey, IpTrafficStatsValue, TRAFFIC_STATS_MAP_SIZE)
DEFINE_BPF_MAP(tsm_overall_traffic_time_map, HASH, uint32_t, OverallTrafficTimeValue, TRAFFIC_STATS_MAP_SIZE)

static __always_inline int is_system_uid(uint32_t uid) {
    // MIN_SYSTEM_UID is AID_ROOT == 0, so uint32_t is *always* >= 0
    // MAX_SYSTEM_UID is AID_NOBODY == 9999, while AID_APP_START == 10000
    return (uid < AID_APP_START);
}

// "bpf_net_helpers.h" removed. argg! re-invent the wheel.
static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to,
                                 int len) = (void*)BPF_FUNC_skb_load_bytes;

static uint32_t (*bpf_get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;

// Android only supports little endian architectures
#define htons(x) (__builtin_constant_p(x) ? ___constant_swab16(x) : __builtin_bswap16(x))
#define htonl(x) (__builtin_constant_p(x) ? ___constant_swab32(x) : __builtin_bswap32(x))
#define ntohs(x) htons(x)
#define ntohl(x) htonl(x)

//< APE : start
static inline bool ape_is_uid_allowed(struct __sk_buff* skb){

    uint32_t sock_uid = bpf_get_socket_uid(skb);
    if (is_system_uid(sock_uid)) return BPF_MATCH;

    OemUidOwnerValue *semApeMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (semApeMatch)
        return semApeMatch->rule & SEMAPE_WLAN_MATCH;

    return BPF_NOMATCH;
}

/* LO, Private IP and ZeroConfig IP to be exempted */
static int isPrivate(__u32 ip_addr) {

    return ((ip_addr & 0xFF000000) == 0x7F000000) /* 127.0.0.0/8    (loopback) */ ||
           ((ip_addr & 0xFFFF0000) == 0xC0A80000) /* 192.168.0.0/16 (private)  */ ||
           ((ip_addr & 0xFF000000) == 0x0A000000) /* 10.0.0.0/8     (private)  */ ||
           ((ip_addr & 0xFFF00000) == 0xAC100000) /* 172.16.0.0/12  (private)  */ ||
           ((ip_addr & 0xFFFF0000) == 0xA9FE0000) /* 169.254.0.0/16 (zeroconf) */;
}

static inline void ape_mark_uid_dest_map(struct __sk_buff* skb, int offset){
    __u32 key = ntohl(load_word(skb, offset));
    __u8 mark = 1;

    bpf_ape_uid_dest_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
}

static inline void ape_mark_uid_dest6_map(__u16 key){
    __u8 mark = 1;

    bpf_ape_uid_dest6_map_update_elem(&key, &mark /* value = 1 */, 0 /*flags = BPF_ANY*/);
}

//SEC("schedcls/ingress/ape_ether")
DEFINE_BPF_PROG("schedcls/ingress/ape_ether", AID_ROOT, AID_SYSTEM, sched_cls_ingress_ape_ether)
(struct __sk_buff* skb) {

    if (skb->protocol == htons(ETH_P_IP)) {
        __u32 key = ntohl(load_word(skb, IP_ETH_OFF_SRC));
        __u8 *mark = bpf_ape_uid_dest_map_lookup_elem(&key);
        if (mark || isPrivate(ntohl(key))) {
            //skb->priority = 7;
            return TC_ACT_OK;
        }
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        int offset = ETH_HLEN + IPV6_PROTO_OFF;
        int ret = 0;
        uint8_t proto;
        ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
        if (!ret) {
            if (proto == IPPROTO_TCP) {
                __u16 key = load_half(skb, TCP6_DPORT_OFF);
                __u8 *mark = bpf_ape_uid_dest6_map_lookup_elem(&key);
                if (mark) {
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            } else if (proto == IPPROTO_UDP) {
                __u16 key = load_half(skb, UDP6_DPORT_OFF);
                __u8 *mark = bpf_ape_uid_dest6_map_lookup_elem(&key);
                if (mark) {
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            }
        }
    }
    skb->priority = 0;
    return TC_ACT_UNSPEC;
}

//SEC("schedcls/egress/ape_ether")
DEFINE_BPF_PROG("schedcls/egress/ape_ether", AID_ROOT, AID_SYSTEM, sched_cls_egress_ape_ether)
(struct __sk_buff* skb) {

    bool is_allowed =  ape_is_uid_allowed(skb);
    if (skb->protocol == htons(ETH_P_IP)) {
        __u32 key = load_word(skb, IP_ETH_OFF_DST);
        if (isPrivate(key)) {
            return TC_ACT_OK;
        }
    }
    
    if (is_allowed) {
        if (skb->protocol == htons(ETH_P_IP)) {
            ape_mark_uid_dest_map(skb, IP_ETH_OFF_DST);
            //skb->priority = 7;
            return TC_ACT_OK;
        } else if (skb->protocol == htons(ETH_P_IPV6)) {
            int ret = 0;
            int offset = ETH_HLEN + IPV6_PROTO_OFF;
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, offset, &proto, 1);
            if (!ret) {
                if (proto == IPPROTO_TCP) {
                    __u16 key = load_half(skb, TCP6_SPORT_OFF);
                    ape_mark_uid_dest6_map(key);
                    //skb->priority = 7;
                    return TC_ACT_OK;
                } else if (proto == IPPROTO_UDP) {
                    __u16 key = load_half(skb, UDP6_SPORT_OFF);
                    ape_mark_uid_dest6_map(key);
                    //skb->priority = 7;
                    return TC_ACT_OK;
                }
            }
        }
    }

    //skb->priority = 0;
    return TC_ACT_UNSPEC;
}
// > APE : end

//< QBOX : START
DEFINE_BPF_PROG("skfilter/qbox/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_qbox_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    // for SYSTEM UID no need to lookup. Only for user range
    if (is_system_uid(sock_uid)) return BPF_NOMATCH;

    OemUidOwnerValue* qboxMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (qboxMatch) return qboxMatch->rule & QBOX_MATCH;
    return BPF_NOMATCH;
}
//> QBOX : END

// < GMS-CORE : start
DEFINE_BPF_PROG("skfilter/mobilefw/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_mobilefw_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    OemUidOwnerValue* firewallMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
        if (firewallMatch) {
            return firewallMatch->rule 
                & FIREWALL_MOBILE_DATA_MATCH ? BPF_MATCH : BPF_NOMATCH;
        }
    return BPF_NOMATCH;
}

DEFINE_BPF_PROG("skfilter/wlanfw/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_wlanfw_prog)
(struct __sk_buff* skb) {
    uint32_t sock_uid = bpf_get_socket_uid(skb);
    OemUidOwnerValue* firewallMatch = bpf_oem_uid_owner_map_lookup_elem(&sock_uid);
    if (firewallMatch) {
        return firewallMatch->rule 
            & FIREWALL_WLAN_MATCH ? BPF_MATCH : BPF_NOMATCH;
    }
    return BPF_NOMATCH;
}
// > GMS-CORE : end

//#endif

#define RETURN_TO_SLEEP_TIME 50000000
DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/tsm_ether", AID_ROOT, AID_SYSTEM, sched_cls_ingress_tsm_ether)
(struct __sk_buff* skb) {
    if (skb->pkt_type != PACKET_HOST) return TC_ACT_PIPE;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_PIPE;
    }

    bool isIpV4 = skb->protocol == htons(ETH_P_IP) ? 1 : 0;
    bool isIpV6 = skb->protocol == htons(ETH_P_IPV6) ? 1 : 0;

    if (isIpV4 || isIpV6) {
        UidStatsKey statsKey;
        bool validPacket = 0;
        int udpPacketCnt = 0;
        int tcpPacketCnt = 0;

        if (isIpV4) {
            statsKey.key = ntohl(load_word(skb, IP_ETH_OFF_SRC));
            uint8_t proto;
            int ret = bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                udpPacketCnt = 1;
                validPacket = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                tcpPacketCnt = 1;
                validPacket = 1;
            }
        } else {
            uint8_t proto;
            int ret = bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                statsKey.key = (uint32_t)load_half(skb, UDP6_DPORT_OFF);
                udpPacketCnt = 1;
                validPacket = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                statsKey.key = (uint32_t)load_half(skb, TCP6_DPORT_OFF);
                tcpPacketCnt = 1;
                validPacket = 1;
            }
        }

        if (validPacket) {
            uint64_t curTime = bpf_ktime_get_ns();
            uint64_t packetLen = skb->len;
            uint32_t onePacket = 1;
            InterPacketRxStatsValue *interPacketStatsVal = bpf_tsm_inter_packet_rx_stats_map_lookup_elem(&statsKey);
            if (interPacketStatsVal) {
                InterPacketRxStatsValue newStats = *interPacketStatsVal;
                if (interPacketStatsVal->maxRxPacketSize < packetLen) {
                    newStats.maxRxPacketSize = packetLen;
                }
                if (interPacketStatsVal->minRxPacketSize > packetLen) {
                    newStats.minRxPacketSize = packetLen;
                }
                if (interPacketStatsVal->latestRxTime != 0 && curTime > interPacketStatsVal->latestRxTime) {
                    uint64_t interPacketTime = curTime - interPacketStatsVal->latestRxTime;
                    if (interPacketStatsVal->maxRxInterPacketTime2 < interPacketTime) {
                        if (interPacketStatsVal->maxRxInterPacketTime < interPacketTime) {
                            newStats.maxRxInterPacketTime2 = interPacketStatsVal->maxRxInterPacketTime;
                            newStats.maxRxInterPacketTime = interPacketTime;
                        } else {
                            newStats.maxRxInterPacketTime2 = interPacketTime;
                        }
                    }
                }
                newStats.latestRxTime = curTime;
                bpf_tsm_inter_packet_rx_stats_map_update_elem(&statsKey, &newStats, 0);
            } else {
                InterPacketRxStatsValue initInterPacketRxStatsValue = {0};
                initInterPacketRxStatsValue.maxRxPacketSize = packetLen;
                initInterPacketRxStatsValue.minRxPacketSize = packetLen;
                initInterPacketRxStatsValue.latestRxTime = curTime;
                bpf_tsm_inter_packet_rx_stats_map_update_elem(&statsKey, &initInterPacketRxStatsValue, 0);
            }

            uint32_t trafficTimeKey = TSM_KEY_OVERALL_TRAFFIC_TIME;
            OverallTrafficTimeValue *lastTimeValue =
                    bpf_tsm_overall_traffic_time_map_lookup_elem(&trafficTimeKey);
            if (lastTimeValue) {
                OverallTrafficTimeValue newStats = *lastTimeValue;
                uint64_t wakeTime = 0;
                if (lastTimeValue->latestRxTime > lastTimeValue->latestTxTime) {
                    wakeTime = curTime - lastTimeValue->latestRxTime;
                } else {
                    wakeTime = curTime - lastTimeValue->latestTxTime;
                }
                if (wakeTime < RETURN_TO_SLEEP_TIME) {
                    newStats.accumulatedWakeTime = lastTimeValue->accumulatedWakeTime + wakeTime;
                }

                if (lastTimeValue->latestRxTime != 0 && curTime > lastTimeValue->latestRxTime) {
                    uint64_t interPacketTime = curTime - lastTimeValue->latestRxTime;
                    if (lastTimeValue->maxRxInterPacketTime2 < interPacketTime) {
                        if (lastTimeValue->maxRxInterPacketTime < interPacketTime) {
                            newStats.maxRxInterPacketTime2 = lastTimeValue->maxRxInterPacketTime;
                            newStats.maxRxInterPacketTime = interPacketTime;
                        } else {
                            newStats.maxRxInterPacketTime2 = interPacketTime;
                        }
                    }
                }
                newStats.latestRxTime = curTime;
                bpf_tsm_overall_traffic_time_map_update_elem(&trafficTimeKey, &newStats, 0);
            } else {
                OverallTrafficTimeValue initValue = {0};
                initValue.latestRxTime = curTime;
                initValue.minTxInterPacketTime = 50000000;
                bpf_tsm_overall_traffic_time_map_update_elem(&trafficTimeKey, &initValue, 0);
            }

            IpTrafficStatsValue *ipTrafficStatsVal = bpf_tsm_traffic_stats_map_lookup_elem(&statsKey);
            if (ipTrafficStatsVal) {
                __sync_fetch_and_add(&ipTrafficStatsVal->rxPackets, onePacket);
                __sync_fetch_and_add(&ipTrafficStatsVal->rxBytes, packetLen);
                __sync_fetch_and_add(&ipTrafficStatsVal->tcpPackets, tcpPacketCnt);
                __sync_fetch_and_add(&ipTrafficStatsVal->udpPackets, udpPacketCnt);
            } else {
                IpTrafficStatsValue initValue = {0};
                initValue.rxPackets = onePacket;
                initValue.rxBytes = packetLen;
                initValue.tcpPackets = tcpPacketCnt;
                initValue.udpPackets = udpPacketCnt;
                if (isIpV6) {
                    struct ethhdr  *eth  = data;
                    struct ipv6hdr* ip6 = (void*)(eth + 1);
                    if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_PIPE;
                    initValue.ipv6Addr1 = ip6->saddr.s6_addr32[0];
                    initValue.ipv6Addr2 = ip6->saddr.s6_addr32[1];
                    initValue.ipv6Addr3 = ip6->saddr.s6_addr32[2];
                    initValue.ipv6Addr4 = ip6->saddr.s6_addr32[3];
                    initValue.ipVersion = 6;
                } else {
                    initValue.ipv4Addr = statsKey.key;
                    initValue.ipVersion = 4;
                }
                bpf_tsm_traffic_stats_map_update_elem(&statsKey, &initValue, 0);
            }
        }
        return TC_ACT_OK;
    }
    return TC_ACT_PIPE;
}

DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/tsm_ether", AID_ROOT, AID_SYSTEM, sched_cls_egress_tsm_ether)
(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_PIPE;
    }

    bool isIpV4 = skb->protocol == htons(ETH_P_IP) ? 1 : 0;
    bool isIpV6 = skb->protocol == htons(ETH_P_IPV6) ? 1 : 0;

    if (isIpV4 || isIpV6) {
        UidStatsKey statsKey;
        bool validPacket = 0;
        int udpPacketCnt = 0;
        int tcpPacketCnt = 0;
        if (isIpV4) {
            statsKey.key = ntohl(load_word(skb, IP_ETH_OFF_DST));
            uint8_t proto;
            int ret = bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                udpPacketCnt = 1;
                validPacket = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                tcpPacketCnt = 1;
                validPacket = 1;
            }
        } else {
            uint8_t proto;
            int ret = bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                statsKey.key = (uint32_t)load_half(skb, UDP6_SPORT_OFF);
                udpPacketCnt = 1;
                validPacket = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                statsKey.key = (uint32_t)load_half(skb, TCP6_SPORT_OFF);
                tcpPacketCnt = 1;
                validPacket = 1;
            }
        }
 
        if (validPacket) {
            uint32_t sock_uid = bpf_get_socket_uid(skb);
            uint64_t curTime = bpf_ktime_get_ns();
            uint64_t packetLen = skb->len;
            uint32_t onePacket = 1;

            InterPacketTxStatsValue *interPacketStatsVal = bpf_tsm_inter_packet_tx_stats_map_lookup_elem(&statsKey);
            if (interPacketStatsVal) {
                InterPacketTxStatsValue newStats = *interPacketStatsVal;
                if (interPacketStatsVal->maxTxPacketSize < packetLen) {
                    newStats.maxTxPacketSize = packetLen;
                }
                if (interPacketStatsVal->minTxPacketSize > packetLen) {
                    newStats.minTxPacketSize = packetLen;
                }
                if (interPacketStatsVal->latestTxTime != 0 && curTime > interPacketStatsVal->latestTxTime) {
                    uint64_t interPacketTime = curTime - interPacketStatsVal->latestTxTime;
                    if (interPacketStatsVal->maxTxInterPacketTime < interPacketTime) {
                        newStats.maxTxInterPacketTime = interPacketTime;
                    }
                    if (interPacketStatsVal->minTxInterPacketTime > interPacketTime) {
                        newStats.minTxInterPacketTime = interPacketTime;
                    }
                }
                newStats.latestTxTime = curTime;
                bpf_tsm_inter_packet_tx_stats_map_update_elem(&statsKey, &newStats, 0);
            } else {
                InterPacketTxStatsValue initInterPacketTxStatsValue = {0};
                initInterPacketTxStatsValue.maxTxPacketSize = packetLen;
                initInterPacketTxStatsValue.minTxPacketSize = packetLen;
                initInterPacketTxStatsValue.latestTxTime = curTime;
                initInterPacketTxStatsValue.minTxInterPacketTime = 50000000;
                bpf_tsm_inter_packet_tx_stats_map_update_elem(&statsKey, &initInterPacketTxStatsValue, 0);
            }

            uint32_t trafficTimeKey = TSM_KEY_OVERALL_TRAFFIC_TIME;
            OverallTrafficTimeValue *lastTimeValue =
                    bpf_tsm_overall_traffic_time_map_lookup_elem(&trafficTimeKey);
            if (lastTimeValue) {
                OverallTrafficTimeValue newStats = *lastTimeValue;
                uint64_t wakeTime = 0;
                if (lastTimeValue->latestRxTime > lastTimeValue->latestTxTime) {
                    wakeTime = curTime - lastTimeValue->latestRxTime;
                } else {
                    wakeTime = curTime - lastTimeValue->latestTxTime;
                }
                if (wakeTime < RETURN_TO_SLEEP_TIME) {
                    newStats.accumulatedWakeTime = lastTimeValue->accumulatedWakeTime + wakeTime;
                }

                if (lastTimeValue->latestTxTime != 0 && curTime > lastTimeValue->latestTxTime) {
                    uint64_t interPacketTime = curTime - lastTimeValue->latestTxTime;
                    if (lastTimeValue->maxTxInterPacketTime < interPacketTime) {
                        newStats.maxTxInterPacketTime = interPacketTime;
                    }
                    if (lastTimeValue->minTxInterPacketTime > interPacketTime) {
                        newStats.minTxInterPacketTime = interPacketTime;
                    }
                }
                newStats.latestTxTime = curTime;
                bpf_tsm_overall_traffic_time_map_update_elem(&trafficTimeKey, &newStats, 0);
            } else {
                OverallTrafficTimeValue initValue = {0};
                initValue.latestTxTime = curTime;
                initValue.minTxInterPacketTime = 50000000;
                bpf_tsm_overall_traffic_time_map_update_elem(&trafficTimeKey, &initValue, 0);
            }

            IpTrafficStatsValue *ipTrafficStatsVal = bpf_tsm_traffic_stats_map_lookup_elem(&statsKey);
            if (ipTrafficStatsVal && ipTrafficStatsVal->uid != 0) {
                __sync_fetch_and_add(&ipTrafficStatsVal->txPackets, onePacket);
                __sync_fetch_and_add(&ipTrafficStatsVal->txBytes, packetLen);
                __sync_fetch_and_add(&ipTrafficStatsVal->tcpPackets, tcpPacketCnt);
                __sync_fetch_and_add(&ipTrafficStatsVal->udpPackets, udpPacketCnt);
            } else {
                IpTrafficStatsValue initValue = {0};
                initValue.uid = sock_uid;
                initValue.txPackets = onePacket;
                initValue.txBytes = packetLen;
                initValue.tcpPackets = tcpPacketCnt;
                initValue.udpPackets = udpPacketCnt;
                initValue.firstTxTime = curTime;
                if (ipTrafficStatsVal) {
                    initValue.rxPackets = ipTrafficStatsVal->rxPackets;
                    initValue.rxBytes = ipTrafficStatsVal->rxBytes;
                    initValue.tcpPackets = ipTrafficStatsVal->tcpPackets;
                    initValue.udpPackets = ipTrafficStatsVal->udpPackets;
                }
                if (isIpV6) {
                    struct ethhdr  *eth  = data;
                    struct ipv6hdr* ip6 = (void*)(eth + 1);
                    if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_PIPE;
                    initValue.ipv6Addr1 = ip6->daddr.s6_addr32[0];
                    initValue.ipv6Addr2 = ip6->daddr.s6_addr32[1];
                    initValue.ipv6Addr3 = ip6->daddr.s6_addr32[2];
                    initValue.ipv6Addr4 = ip6->daddr.s6_addr32[3];
                    initValue.ipVersion = 6;
                } else {
                    initValue.ipv4Addr = statsKey.key;
                    initValue.ipVersion = 4;
                }
                bpf_tsm_traffic_stats_map_update_elem(&statsKey, &initValue, 0);
            }
        }

        return TC_ACT_OK;
    }
    return TC_ACT_PIPE;
}

LICENSE("Apache 2.0");
CRITICAL("Sem eBPF UID");
