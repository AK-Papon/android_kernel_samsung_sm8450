/******************************************************************************************************
 *  FILENAME: semSmartHS.c
 *
 *  DESCRIPTION :
 *        eBPF based functions to monitor and control the connected hotspot client.
 *
 *  AUTHOR : Madhan Raj Kanagarathinam
 *  DATE: 2023
 *  VERSION: 1.1
 *
 *  NOTE:
 *  1.1: The rule-based eBPF functionalities are modified by ML-based approach
 *  
 *
 *  COPYRIGHT BY Samsung Electronics. ALL RIGHTS RESERVED
 ******************************************************************************************************/
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
#include "bpf_helpers.h"
#include <ss_bpf_shared.h>
#include <netinet/in.h>  // Required for using htonl and htons

#include <linux/pkt_cls.h>
#include <linux/filter.h>

// bionic kernel uapi linux/udp.h header is munged...
#define __kernel_udphdr udphdr
#include <linux/udp.h>


#define IPV6_PROTO_OFF offsetof(struct ipv6hdr, nexthdr)
#define IP_PROTO_OFF offsetof(struct iphdr, protocol)
#define IP_OFF_SRC   (offsetof(struct iphdr, saddr))
#define IP_OFF_DST   (offsetof(struct iphdr, daddr))
#define TCP_DPORT_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP_SPORT_OFF     (ETH_HLEN + sizeof(struct iphdr)  + offsetof(struct tcphdr, source))
#define UDP_DPORT_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_SPORT_OFF     (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define TCP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define TCP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))
#define UDP6_DPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest))
#define UDP6_SPORT_OFF    (ETH_HLEN + sizeof(struct ipv6hdr) + offsetof(struct udphdr, source))
#define IP_ETH_OFF_SRC    (ETH_HLEN + IP_OFF_SRC)
#define IP_ETH_OFF_DST    (ETH_HLEN + IP_OFF_DST)

// "bpf_net_helpers.h" removed. argg! re-invent the wheel.
static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to,
                                 int len) = (void*)BPF_FUNC_skb_load_bytes;

#define bpf_debug(fmt, ...)  \
    ({                       \
     char ____fmt[] = fmt;\
     bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
     })

// "bpf_net_helpers.h" removed. argg! re-invent the wheel.
/*static int (*bpf_skb_load_bytes)(struct __sk_buff* skb, int off, void* to,
                                 int len) = (void*)BPF_FUNC_skb_load_bytes;*/
static uint32_t (*bpf_get_socket_uid)(struct __sk_buff* skb) = (void*)BPF_FUNC_get_socket_uid;

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
#define DEFAULT_MTU_SIZE 1500
#define TCP_TS_SIZE 12
#define IPV4_TCP_SIZE sizeof(struct iphdr) + sizeof(struct tcphdr) + TCP_TS_SIZE
#define IPV6_TCP_SIZE sizeof(struct ipv6hdr) + sizeof(struct tcphdr) + TCP_TS_SIZE

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
#define MBB_MAC_BYTE_MAP_SIZE 50
#define MBB_ARRAY_MAP_SIZE 10

DEFINE_BPF_MAP(mbb_mac_data_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_egress_data_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)

DEFINE_BPF_MAP(mbb_mac_total_map, HASH, uint32_t, uint64_t, MBB_ARRAY_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_pause_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_gpause_map, HASH, uint32_t, uint64_t, MBB_ARRAY_MAP_SIZE)
DEFINE_BPF_MAP(mbb_mac_rt_data_map, HASH, uint64_t, uint64_t, MBB_MAC_BYTE_MAP_SIZE)
//#endif

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_PRIORITIZE_TRAFFIC
#define IP_PRIORITY_MAP_SIZE 100
DEFINE_BPF_MAP(mbb_ip_priority_map, HASH, IpKey, uint8_t, IP_PRIORITY_MAP_SIZE)

#define ETRAFFIC_STATS_MAP_SIZE 1024
DEFINE_BPF_MAP(etsm_inter_packet_rx_stats_map, HASH, IpKey, InterPacketRxStatsValue, ETRAFFIC_STATS_MAP_SIZE)
DEFINE_BPF_MAP(etsm_inter_packet_tx_stats_map, HASH, IpKey, InterPacketTxStatsValue, ETRAFFIC_STATS_MAP_SIZE)
DEFINE_BPF_MAP(etsm_traffic_stats_map, HASH, IpKey, IpTrafficStatsValue, ETRAFFIC_STATS_MAP_SIZE)


//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_DATA_USAGE
//< S-HS : START
/***************************************************************
* Function:  size_without_gro
* ------------------------------------
* Due to Genreric Recieve Offloading (GRO) function, we can see
* multiple packets with same header to reduce per-packet processing
* overhead. However, on-the-air only the actual MTU of the packets
* are transmitted. Though, we see a higher number, we have to compute
* the data bytes with the actual header on-the-air. This function
* computes the size with actual overhead. Known problem: We add the
* the size of TCP packet even for UDP packets. Google assumes that
* offloading is not possible in UDP protocol. However, in the
* UDP-based QUIC protocol, UDP offloading is possible.
*
*
* byte: the packet len after GRO
* overhead: Determines the TCP/IP L3/L4 packet overhead on the wire
*
* returns: probable actual size before GRO
*****************************************************************/

static inline uint64_t size_without_gro(uint64_t byte, int overhead) {
    if(byte > DEFAULT_MTU_SIZE) {
        int packets = 1;
        int mss = DEFAULT_MTU_SIZE - overhead;
        uint64_t payload = byte - overhead;
        packets = (payload + mss - 1) / mss;
        byte = overhead * packets + payload;
    }
    return byte;
}

/***************************************************************
* Function:  pause_or_update_datausage
* ------------------------------------
* updates the data usage of the clients, based on the MAC address.
* additionally, it also determines if the specific client has reached its allowed quota.
*
*
* key: MAC key in uint64_t converted format
* byte: the packet len to be updated
* overhead: Determines the TCP/IP L3/L4 packet overhead on the wire
*
*
* returns: if the specific client has to be paused or continue.
*****************************************************************/
static inline bool pause_or_update_datausage(uint64_t key, uint64_t byte, int overhead) {
    uint32_t globalKey = 1;
    uint64_t *pauseQuota = bpf_mbb_mac_pause_map_lookup_elem(&key);
    uint64_t *pauseGQuota = bpf_mbb_mac_gpause_map_lookup_elem(&globalKey);

    uint64_t *byteClient = bpf_mbb_mac_data_map_lookup_elem(&key);
    uint64_t *byteTotal = bpf_mbb_mac_total_map_lookup_elem(&globalKey);

    uint64_t curbyte = size_without_gro(byte, overhead);

    if(byteTotal) {
        if(pauseGQuota && (*byteTotal + curbyte) > *pauseGQuota)
            return 1;
    } else {
        if(pauseGQuota && curbyte > *pauseGQuota)
            return 1;
    }

    // If byteClient, then there is already existing stats for the MAC key
    if(byteClient) {
        // Check if the pauseQuota is set for the client and if current size can exceed the limit
        if(pauseQuota && (*byteClient + curbyte) > *pauseQuota)
            return 1;

        __sync_fetch_and_add(byteClient, curbyte);
    } else {
        // Pause even if it is first ever data packet (TCP/UDP)
        if(pauseQuota && curbyte > *pauseQuota)
            return 1;

        // first ever update of data curbyte.
        bpf_mbb_mac_data_map_update_elem(&key, &curbyte, 0);
    }

    if(byteTotal) __sync_fetch_and_add(byteTotal, curbyte);
    else bpf_mbb_mac_total_map_update_elem(&globalKey, &curbyte, 0);

    // dont pause, update completed
    return 0;

}

/***************************************************************
* Function:  ingress_mbb_swlan
* ------------------------------------
* The new Schedule class BPF program to update the data usage, pausing.
* Additionally, eTSM is introduced for per-session monitoring.
*
*
* skb: Socket Buffer
*
*
* returns: TC_ACT_SHOT if packet to be dropped, TC_ACT_UNSPEC otherwise.
*****************************************************************/

DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/mbb_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_mbb_swlan)
(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const size_t l2_header_size = sizeof(struct ethhdr);
    bool isIpV4 = skb->protocol == htons(ETH_P_IP) ? 1 : 0;
    bool isIpV6 = skb->protocol == htons(ETH_P_IPV6) ? 1 : 0;

    //Not a good packet
    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC; // Pipe or unspec? should we let the forward handle it ?
    }

    if(isIpV4 || isIpV6) {
        struct ethhdr *eth  = data;
        IpKey statsKey = {0};
        int udpPacketCnt = 0;
        int tcpPacketCnt = 0;
        bool isValidPacket = 0;
        uint32_t sport = 0;
        uint32_t dport = 0;

        uint64_t byte = skb->len;

        if(isIpV4) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;

                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // In case of MHS, the port is the key
                sport = (uint32_t)tcph->source;   // Previous key             
                dport = (uint32_t)tcph->dest; 
                tcpPacketCnt = 1;
                statsKey.k1 = ntohl(load_word(skb, IP_ETH_OFF_DST));
                isValidPacket = 1;
            } 
            else {
                if (ip->protocol == IPPROTO_UDP) {
                    struct udphdr* udph = (void*)(ip + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;
                    sport = (uint32_t)udph->source;    // Previous key 
                    dport = (uint32_t)udph->dest;
                    udpPacketCnt = 1;
                    statsKey.k1 = ntohl(load_word(skb, IP_ETH_OFF_DST));
                    isValidPacket = 1;
                }
            }
        } else {
            // Just to keep the loader happy - one time load failed
            if(isIpV6) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                    sport = (uint32_t)tcph->source; 
                    dport = (uint32_t)tcph->dest;
                    tcpPacketCnt = 1;
                    statsKey.k1 = ip6->daddr.s6_addr32[0];
                    statsKey.k2 = ip6->daddr.s6_addr32[1];
                    statsKey.k3 = ip6->daddr.s6_addr32[2];
                    statsKey.k4 = ip6->daddr.s6_addr32[3];
                    isValidPacket = 1;
                } else {
                    if (ip6->nexthdr == IPPROTO_UDP) {
                        struct udphdr* udph = (void*)(ip6 + 1);
                        if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;
                        sport = (uint32_t)udph->source; 
                        dport = (uint32_t)udph->dest;
                        udpPacketCnt = 1;
                        statsKey.k1 = ip6->daddr.s6_addr32[0];
                        statsKey.k2 = ip6->daddr.s6_addr32[1];
                        statsKey.k3 = ip6->daddr.s6_addr32[2];
                        statsKey.k4 = ip6->daddr.s6_addr32[3];
                        isValidPacket = 1;
                    }
                }
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000)) {   // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000)) {    // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // In the upstream direction do not forward traffic within the same /64 subnet.
                if ((src32 == dst32) && (ip6->saddr.s6_addr32[1] == ip6->daddr.s6_addr32[1])) {
                       return TC_ACT_UNSPEC;
                }
            }
        }

        __u32 macpart1 = eth->h_source[5] | (eth->h_source[4] << 8) | (eth->h_source[3] << 16) | (eth->h_source[2] << 24);
        __u32 macpart2 = eth->h_source[1] | (eth->h_source[0] << 8);
        uint64_t key = ((uint64_t)macpart2)<<32 | macpart1;

        if (key == 281474976710655 || key == 1101088686331 || key == 1101088686102) {
            return TC_ACT_UNSPEC;
        }

        if(pause_or_update_datausage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE))
            return TC_ACT_SHOT;
        else {
            uint32_t sock_uid = bpf_get_socket_uid(skb); // just to make sure TxStats is updated
            if (isValidPacket) {
                uint64_t curTime = bpf_ktime_get_ns();
                uint64_t curbyte = size_without_gro(byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                uint64_t packetLen = curbyte; // Bytes with header adjustment
                uint32_t onePacket = (curbyte / DEFAULT_MTU_SIZE) + 1; // Number of packets without GRO
                if (tcpPacketCnt) tcpPacketCnt = onePacket;
                if (udpPacketCnt) udpPacketCnt = onePacket;

                uint64_t perPacketLen = 1500;
                if(packetLen < 1500) perPacketLen = packetLen;
                
                InterPacketTxStatsValue *interPacketStatsVal = bpf_etsm_inter_packet_tx_stats_map_lookup_elem(&statsKey);
                if (interPacketStatsVal) {
                    InterPacketTxStatsValue newStats = *interPacketStatsVal;
                    if (interPacketStatsVal->maxTxPacketSize < perPacketLen) {
                        newStats.maxTxPacketSize = perPacketLen;
                    }
                    if (interPacketStatsVal->minTxPacketSize > perPacketLen) {
                        newStats.minTxPacketSize = perPacketLen;
                    }
                    if (interPacketStatsVal->latestTxTime != 0) {
                        uint64_t interPacketTime = curTime - interPacketStatsVal->latestTxTime;
                        if (interPacketStatsVal->maxTxInterPacketTime < interPacketTime) {
                            newStats.maxTxInterPacketTime = interPacketTime;
                        }
                        if (interPacketStatsVal->minTxInterPacketTime > interPacketTime) {
                            newStats.minTxInterPacketTime = interPacketTime;
                        }
                    }
                    newStats.latestTxTime = curTime;
                    bpf_etsm_inter_packet_tx_stats_map_update_elem(&statsKey, &newStats, 0);
                } else {
                    InterPacketTxStatsValue initInterPacketTxStatsValue = {0};
                    initInterPacketTxStatsValue.maxTxPacketSize = perPacketLen;
                    initInterPacketTxStatsValue.minTxPacketSize = perPacketLen;
                    initInterPacketTxStatsValue.latestTxTime = curTime;
                    initInterPacketTxStatsValue.minTxInterPacketTime = 50000000;
                    initInterPacketTxStatsValue.maxTxInterPacketTime = 0;
                    bpf_etsm_inter_packet_tx_stats_map_update_elem(&statsKey, &initInterPacketTxStatsValue, 0);
                }
                
                IpTrafficStatsValue *ipTrafficStatsVal = bpf_etsm_traffic_stats_map_lookup_elem(&statsKey);
                if (ipTrafficStatsVal) {
                    __sync_fetch_and_add(&ipTrafficStatsVal->txPackets, onePacket);
                    __sync_fetch_and_add(&ipTrafficStatsVal->txBytes, packetLen);
                    __sync_fetch_and_add(&ipTrafficStatsVal->tcpPackets, tcpPacketCnt);
                    __sync_fetch_and_add(&ipTrafficStatsVal->udpPackets, udpPacketCnt);
                    if (ipTrafficStatsVal->uid == 0) {
                        __sync_fetch_and_add(&ipTrafficStatsVal->uid, sock_uid);
                        __sync_fetch_and_add(&ipTrafficStatsVal->firstTxTime, curTime);
                    }
                } else {
                    IpTrafficStatsValue initValue = {0};
                    initValue.uid = sock_uid; // uid is no use in MHS UID_TETHER - dummy
                    initValue.txPackets = onePacket;
                    initValue.txBytes = packetLen;
                    initValue.tcpPackets = tcpPacketCnt;
                    initValue.udpPackets = udpPacketCnt;
                    initValue.firstTxTime = curTime;
                    initValue.sport = sport;
                    initValue.dport = dport;
                    initValue.cliMacAddr = key;
                    if (isIpV6) {
                        struct ethhdr  *eth  = data;
                        struct ipv6hdr* ip6 = (void*)(eth + 1);
                        if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_PIPE;
                        initValue.ipv6Addr1 = ip6->daddr.s6_addr32[0];
                        initValue.ipv6Addr2 = ip6->daddr.s6_addr32[1];
                        initValue.ipv6Addr3 = ip6->daddr.s6_addr32[2];
                        initValue.ipv6Addr4 = ip6->daddr.s6_addr32[3];
                        initValue.ipv6sAddr1 = ip6->saddr.s6_addr32[0];
                        initValue.ipv6sAddr2 = ip6->saddr.s6_addr32[1];
                        initValue.ipv6sAddr3 = ip6->saddr.s6_addr32[2];
                        initValue.ipv6sAddr4 = ip6->saddr.s6_addr32[3];
                        initValue.ipVersion = 6;
                    } else {
                        initValue.ipv4Addr = ntohl(load_word(skb, IP_ETH_OFF_DST));
                        initValue.ipv4sAddr = ntohl(load_word(skb, IP_ETH_OFF_SRC));
                        initValue.ipVersion = 4;
                    }
                    bpf_etsm_traffic_stats_map_update_elem(&statsKey, &initValue, 0);
                }
            }                
        }

    }
    return TC_ACT_UNSPEC;
}


DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/mbb_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_mbb_swlan)
(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const size_t l2_header_size = sizeof(struct ethhdr);
    bool isIpV4 = skb->protocol == htons(ETH_P_IP) ? 1 : 0;
    bool isIpV6 = skb->protocol == htons(ETH_P_IPV6) ? 1 : 0;

    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }

    if(isIpV4 || isIpV6) {
        struct ethhdr  *eth  = data;
        IpKey statsKey = {0};
        int udpPacketCnt = 0;
        int tcpPacketCnt = 0;
        bool isValidPacket = 0;
        uint64_t byte = skb->len;
        uint32_t sport = 0;
        uint32_t dport = 0;

        if(isIpV4) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                dport = (uint32_t)tcph->source; 
                sport = (uint32_t)tcph->dest;  // previous key
                tcpPacketCnt = 1;
                statsKey.k1 = ntohl(load_word(skb, IP_ETH_OFF_SRC));
                isValidPacket = 1;
            } else {
                if (ip->protocol == IPPROTO_UDP) {
                    struct udphdr* udph = (void*)(ip + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;
                    dport = (uint32_t)udph->source; 
                    sport = (uint32_t)udph->dest; // previous key
                    udpPacketCnt = 1;
                    statsKey.k1 = ntohl(load_word(skb, IP_ETH_OFF_SRC));
                    isValidPacket = 1;
                }
            } 
        } else {
            // Just to keep the loader happy
            if(isIpV6) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                    sport = (uint32_t)tcph->dest; 
                    dport = (uint32_t)tcph->source;
                    statsKey.k1 = ip6->saddr.s6_addr32[0];
                    statsKey.k2 = ip6->saddr.s6_addr32[1];
                    statsKey.k3 = ip6->saddr.s6_addr32[2];
                    statsKey.k4 = ip6->saddr.s6_addr32[3];
                    tcpPacketCnt = 1;
                    isValidPacket = 1;
                } else {
                    if (ip6->nexthdr == IPPROTO_UDP) {
                        struct udphdr* udph = (void*)(ip6 + 1);
                        if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;

                        sport = (uint32_t)udph->dest; 
                        dport = (uint32_t)udph->source;
                        statsKey.k1 = ip6->saddr.s6_addr32[0];
                        statsKey.k2 = ip6->saddr.s6_addr32[1];
                        statsKey.k3 = ip6->saddr.s6_addr32[2];
                        statsKey.k4 = ip6->saddr.s6_addr32[3];
                        udpPacketCnt = 1;
                        isValidPacket = 1;
                    }
                }
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000)) {   // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000)) {    // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
            }
        }

        __u32 macpart1 = eth->h_dest[5] | (eth->h_dest[4] << 8) | (eth->h_dest[3] << 16) | (eth->h_dest[2] << 24);
        __u32 macpart2 = eth->h_dest[1] | (eth->h_dest[0] << 8);
        uint64_t key = (((uint64_t)macpart2)<<32) | macpart1;
        if (key == 281474976710655 || key == 1101088686331 || key == 1101088686102) {
            return TC_ACT_UNSPEC;
        }
        if(pause_or_update_datausage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE))
            return TC_ACT_SHOT;
        else {
            uint64_t *byteClientegress = bpf_mbb_mac_egress_data_map_lookup_elem(&key);
            uint64_t curbyte = size_without_gro(byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
            if(byteClientegress) __sync_fetch_and_add(byteClientegress, curbyte);
            else bpf_mbb_mac_egress_data_map_update_elem(&key, &curbyte, 0);
            if(isValidPacket) {
                uint64_t curTime = bpf_ktime_get_ns();
                uint64_t packetLen = curbyte;
                uint32_t onePacket = (curbyte/DEFAULT_MTU_SIZE) + 1; // take the upper
                uint64_t perPacketLen = 1500;
                if(packetLen < 1500) perPacketLen = packetLen;

                if (tcpPacketCnt) tcpPacketCnt = onePacket;
                if (udpPacketCnt) udpPacketCnt = onePacket;

                InterPacketRxStatsValue *interPacketStatsVal = bpf_etsm_inter_packet_rx_stats_map_lookup_elem(&statsKey);
                if (interPacketStatsVal) {
                    InterPacketRxStatsValue newStats = *interPacketStatsVal;
                    if (interPacketStatsVal->maxRxPacketSize < perPacketLen) {
                        newStats.maxRxPacketSize = perPacketLen;
                    }
                    if (interPacketStatsVal->minRxPacketSize > perPacketLen) {
                        newStats.minRxPacketSize = perPacketLen;
                    }
                    if (interPacketStatsVal->latestRxTime != 0) {
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
                    bpf_etsm_inter_packet_rx_stats_map_update_elem(&statsKey, &newStats, 0);
                } else {
                    InterPacketRxStatsValue initInterPacketRxStatsValue = {0};
                    initInterPacketRxStatsValue.maxRxPacketSize = perPacketLen;
                    initInterPacketRxStatsValue.minRxPacketSize = perPacketLen;
                    initInterPacketRxStatsValue.latestRxTime = curTime;
                    initInterPacketRxStatsValue.maxRxInterPacketTime = 0;
                    initInterPacketRxStatsValue.maxRxInterPacketTime2 = 0;
                    bpf_etsm_inter_packet_rx_stats_map_update_elem(&statsKey, &initInterPacketRxStatsValue, 0);
                }
                
                IpTrafficStatsValue *ipTrafficStatsVal = bpf_etsm_traffic_stats_map_lookup_elem(&statsKey);
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
                    // initValue.firstTxTime = curTime;
                    initValue.sport = sport;
                    initValue.dport = dport;
                    initValue.cliMacAddr = key;
                    if (isIpV6) {
                        struct ethhdr  *eth  = data;
                        struct ipv6hdr* ip6 = (void*)(eth + 1);
                        if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_PIPE;
                        initValue.ipv6sAddr1 = ip6->daddr.s6_addr32[0];
                        initValue.ipv6sAddr2 = ip6->daddr.s6_addr32[1];
                        initValue.ipv6sAddr3 = ip6->daddr.s6_addr32[2];
                        initValue.ipv6sAddr4 = ip6->daddr.s6_addr32[3];
                        initValue.ipv6Addr1 = ip6->saddr.s6_addr32[0];
                        initValue.ipv6Addr2 = ip6->saddr.s6_addr32[1];
                        initValue.ipv6Addr3 = ip6->saddr.s6_addr32[2];
                        initValue.ipv6Addr4 = ip6->saddr.s6_addr32[3];
                        initValue.ipVersion = 6;
                    } else {
                        // the key will be port
                        initValue.ipv4Addr = ntohl(load_word(skb, IP_ETH_OFF_SRC));
                        initValue.ipv4sAddr = ntohl(load_word(skb, IP_ETH_OFF_DST));
                        initValue.ipVersion = 4;
                    }
                    bpf_etsm_traffic_stats_map_update_elem(&statsKey, &initValue, 0);
                }
            }
        }
    }
    return TC_ACT_UNSPEC;
}

//#ifdef SEC_PRODUCT_FEATURE_WLAN_SUPPORT_MOBILEAP_PRIORITIZE_TRAFFIC
/****************************************************
  BPF program to check the packets in egress if they
  are real time or non real-time.
  We use the same RT port check to decide RT or NRT
*****************************************************/
DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/mbb_prio_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_mbb_prio_swlan)
(struct __sk_buff* skb) {
    IpKey stats4Key = {0};
    IpKey stats6Key = {0};
    __u8 *ip_exists;
    uint64_t *byteClient;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    uint64_t byte = skb->len;
    const size_t l2_header_size = sizeof(struct ethhdr);
    bool isIpV4 = skb->protocol == htons(ETH_P_IP) ? 1 : 0;
    bool isIpV6 = skb->protocol == htons(ETH_P_IPV6) ? 1 : 0;
    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if(isIpV4 || isIpV6) {
        struct ethhdr  *eth  = data;
        __u32 macpart1 = eth->h_dest[5] | (eth->h_dest[4] << 8) | (eth->h_dest[3] << 16) | (eth->h_dest[2] << 24);
        __u32 macpart2 = eth->h_dest[1] | (eth->h_dest[0] << 8);
        uint64_t key = (((uint64_t)macpart2)<<32) | macpart1;
        if(isIpV4) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                uint32_t src = ntohl(load_word(skb, IP_ETH_OFF_SRC));
                //uint32_t dst = (load_word(skb, IP_ETH_OFF_DST));
                stats4Key.k1 = src;
                //bpf_debug("MBB_debug TCP egress src:%u,dst:%u\n",src,dst);
                ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats4Key);
                    if(ip_exists){
                        //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                        byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                        uint64_t curbyte = size_without_gro(byte, IPV4_TCP_SIZE);
                        // If byteClient, then there is already existing stats for the MAC key
                        if(byteClient) {
                            __sync_fetch_and_add(byteClient, curbyte);
                        } else {
                            // first ever update of data curbyte.
                            bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                        }
                        //bpf_debug("MBB_debug v4 TCP true egress %u\n",stats4Key.k1);
                        return TC_ACT_OK;
                    }
                } else {
                    if (ip->protocol == IPPROTO_UDP) {
                        struct udphdr* udph = (void*)(ip + 1);
                        if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;
                        uint32_t src = ntohl(load_word(skb, IP_ETH_OFF_SRC));
                        //uint32_t dst = (load_word(skb, IP_ETH_OFF_DST));
                        stats4Key.k1 = src;
                        ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats4Key);
                        //bpf_debug("MBB_debug UDP egress src:%u,dst:%u\n",src,dst);
                        if(ip_exists){
                            //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                            byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                            uint64_t curbyte = size_without_gro(byte, IPV4_TCP_SIZE);
                            // If byteClient, then there is already existing stats for the MAC key
                            if(byteClient) {
                                __sync_fetch_and_add(byteClient, curbyte);
                            } else {
                                // first ever update of data curbyte.
                                bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                            }
                            //bpf_debug("MBB_debug  v4 UDP true egress %u\n",stats4Key.k1);
                            return TC_ACT_OK;
                        }
                    }
                }
            } else {
                // Just to keep the loader happy
                if(isIpV6) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                    stats6Key.k1 = ip6->saddr.s6_addr32[0];
                    stats6Key.k2 = ip6->saddr.s6_addr32[1];
                    stats6Key.k3 = ip6->saddr.s6_addr32[2];
                    stats6Key.k4 = ip6->saddr.s6_addr32[3];
                    ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats6Key);
                    //bpf_debug("MBB_debug V6 TCP egress %u\n",stats6Key.k1);
                    if(ip_exists){
                        //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                        byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                        uint64_t curbyte = size_without_gro(byte, IPV6_TCP_SIZE);
                        // If byteClient, then there is already existing stats for the MAC key
                        if(byteClient) {
                            __sync_fetch_and_add(byteClient, curbyte);
                        } else {
                            // first ever update of data curbyte.
                            bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                        }
                        //bpf_debug("MBB_debug V6 TCP true egress %u\n",stats6Key.k1);
                        return TC_ACT_OK;
                    }
                } else {
                    if (ip6->nexthdr == IPPROTO_UDP) {
                        struct udphdr* udph = (void*)(ip6 + 1);
                        if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;
                        stats6Key.k1 = ip6->saddr.s6_addr32[0];
                        stats6Key.k2 = ip6->saddr.s6_addr32[1];
                        stats6Key.k3 = ip6->saddr.s6_addr32[2];
                        stats6Key.k4 = ip6->saddr.s6_addr32[3];
                        ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats6Key);
                        //bpf_debug("MBB_debug V6 UDP egress %u\n",stats6Key.k1);
                        if(ip_exists){
                            //bpf_debug("MBB_debug V6  UDP true egress %u\n",stats6Key.k1);
                            //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                            byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                            uint64_t curbyte = size_without_gro(byte, IPV6_TCP_SIZE);
                            // If byteClient, then there is already existing stats for the MAC key
                            if(byteClient) {
                                __sync_fetch_and_add(byteClient, curbyte);
                            } else {
                                // first ever update of data curbyte.
                                bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                            }
                            return TC_ACT_OK;
                        }
                    }
                }
            }
        }
    }
    return TC_ACT_UNSPEC;
}

/****************************************************
  BPF program to check the packets in ingress if they
  are real time or non real-time.
  We use the same RT port check to decide RT or NRT
*****************************************************/
DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/mbb_prio_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_mbb_prio_swlan)
(struct __sk_buff* skb) {
    IpKey stats4Key = {0};
    IpKey stats6Key = {0};
    __u8 *ip_exists;
    uint64_t *byteClient;
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    uint64_t byte = skb->len;
    const size_t l2_header_size = sizeof(struct ethhdr);
    bool isIpV4 = skb->protocol == htons(ETH_P_IP) ? 1 : 0;
    bool isIpV6 = skb->protocol == htons(ETH_P_IPV6) ? 1 : 0;
    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }
    if(isIpV4 || isIpV6) {
        struct ethhdr  *eth  = data;
        __u32 macpart1 = eth->h_source[5] | (eth->h_source[4] << 8) | (eth->h_source[3] << 16) | (eth->h_source[2] << 24);
        __u32 macpart2 = eth->h_source[1] | (eth->h_source[0] << 8);
        uint64_t key = (((uint64_t)macpart2)<<32) | macpart1;
        if(isIpV4) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                //uint32_t src = (load_word(skb, IP_ETH_OFF_SRC));
                uint32_t dst = ntohl(load_word(skb, IP_ETH_OFF_DST));
                stats4Key.k1 = dst;
                //bpf_debug("MBB_debug TCP ingress ,src:%u,dst:%u\n",src,dst);
                ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats4Key);
                if(ip_exists){
                    //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                    byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                    uint64_t curbyte = size_without_gro(byte, IPV4_TCP_SIZE);
                    // If byteClient, then there is already existing stats for the MAC key
                    if(byteClient) {
                        __sync_fetch_and_add(byteClient, curbyte);
                    } else {
                        // first ever update of data curbyte.
                        bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                    }
                    //bpf_debug("MBB_debug v4 TCP ingress true %u\n",stats4Key.k1);
                    return TC_ACT_OK;
                }
            } else {
                if (ip->protocol == IPPROTO_UDP) {
                    struct udphdr* udph = (void*)(ip + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;
                    //uint32_t src = ntohl(load_word(skb, IP_ETH_OFF_SRC));
                    uint32_t dst = ntohl(load_word(skb, IP_ETH_OFF_DST));
                    stats4Key.k1 = dst;
                    //bpf_debug("MBB_debug UDP ingress, src:%u,dst:%u\n",src,dst);
                    ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats4Key);
                    if(ip_exists){
                        //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                        byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                        uint64_t curbyte = size_without_gro(byte, IPV4_TCP_SIZE);
                        // If byteClient, then there is already existing stats for the MAC key
                        if(byteClient) {
                            __sync_fetch_and_add(byteClient, curbyte);
                        } else {
                            // first ever update of data curbyte.
                            bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                        }
                        //bpf_debug("MBB_debug V4 UDP true ingress %u\n",stats4Key.k1);
                        return TC_ACT_OK;
                    }
                }
            }
        } else {
            // Just to keep the loader happy
            if(isIpV6) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                    stats6Key.k1 = ip6->daddr.s6_addr32[0];
                    stats6Key.k2 = ip6->daddr.s6_addr32[1];
                    stats6Key.k3 = ip6->daddr.s6_addr32[2];
                    stats6Key.k4 = ip6->daddr.s6_addr32[3];
                    ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats6Key);
                    //bpf_debug("MBB_debug V6 TCP ingress %u\n",stats6Key.k1);
                    if(ip_exists){
                        //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                        byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                        uint64_t curbyte = size_without_gro(byte, IPV6_TCP_SIZE);
                        // If byteClient, then there is already existing stats for the MAC key
                        if(byteClient) {
                            __sync_fetch_and_add(byteClient, curbyte);
                        } else {
                            // first ever update of data curbyte.
                            bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                        }
                        //bpf_debug("MBB_debug V6 TCP true ingress %u\n",stats6Key.k1);
                        return TC_ACT_OK;
                    }
                } else {
                    if (ip6->nexthdr == IPPROTO_UDP) {
                        struct udphdr* udph = (void*)(ip6 + 1);
                        if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*udph)) > data_end)  return TC_ACT_UNSPEC;
                        stats6Key.k1 = ip6->daddr.s6_addr32[0];
                        stats6Key.k2 = ip6->daddr.s6_addr32[1];
                        stats6Key.k3 = ip6->daddr.s6_addr32[2];
                        stats6Key.k4 = ip6->daddr.s6_addr32[3];
                        ip_exists = bpf_mbb_ip_priority_map_lookup_elem(&stats6Key);
                        //bpf_debug("MBB_debug V6 UDP ingress %u\n",stats6Key.k1);
                        if(ip_exists){
                            //update_prio_rt_usage(key, byte, isIpV4? IPV4_TCP_SIZE: IPV6_TCP_SIZE);
                            byteClient = bpf_mbb_mac_rt_data_map_lookup_elem(&key);
                            uint64_t curbyte = size_without_gro(byte, IPV6_TCP_SIZE);
                            // If byteClient, then there is already existing stats for the MAC key
                            if(byteClient) {
                                __sync_fetch_and_add(byteClient, curbyte);
                            } else {
                                // first ever update of data curbyte.
                                bpf_mbb_mac_rt_data_map_update_elem(&key, &curbyte, 0);
                            }
                            //bpf_debug("MBB_debug V6 UDP true ingress %u\n",stats6Key.k1);
                            return TC_ACT_OK;
                        }
                    }
                }
            }
        }
    }
    return TC_ACT_UNSPEC;
}

/***************************************************************
* Function:  ingress_mbb_legacy_swlan
* ------------------------------------
* The new Schedule class BPF program to update the data usage, pausing.
*
*
* skb: Socket Buffer
*
*
* returns: TC_ACT_SHOT if packet to be dropped, TC_ACT_UNSPEC otherwise.
*****************************************************************/

DEFINE_OPTIONAL_BPF_PROG("schedcls/ingress/mbb_legacy_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_ingress_mbb_legacy_swlan)
(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const int l2_header_size = sizeof(struct ethhdr);

    //Not a good packet
    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC; // Pipe or unspec? should we let the forward handle it ?
    }

    if(skb->protocol == htons(ETH_P_IP) || skb->protocol == htons(ETH_P_IPV6)) {
        struct ethhdr *eth  = data;

        int ret = 0;
        uint64_t byte = skb->len;
        bool isLimitReached = 0; // To check if the specific client has reached the limit

        if(skb->protocol == htons(ETH_P_IP)) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                //(void) tcph;
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;

                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
            }
        } else {
            // Just to keep the loader happy
            if(skb->protocol == htons(ETH_P_IPV6)) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                }
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000)) {   // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000)) {    // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // In the upstream direction do not forward traffic within the same /64 subnet.
                if ((src32 == dst32) && (ip6->saddr.s6_addr32[1] == ip6->daddr.s6_addr32[1])) {
                       return TC_ACT_UNSPEC;
                }
            }
        }

        __u32 macpart1 = eth->h_source[5] | (eth->h_source[4] << 8) | (eth->h_source[3] << 16) | (eth->h_source[2] << 24);
        __u32 macpart2 = eth->h_source[1] | (eth->h_source[0] << 8);
        uint64_t key = ((uint64_t)macpart2)<<32 | macpart1;
        /*if (key == 281474976710655 || key == 1101088686331 || key == 1101088686102) {
            return TC_ACT_UNSPEC;
        }*/ //TODO:
        if(skb->protocol == htons(ETH_P_IP)) {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
            }
        } else {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            }
        }

        // We drop any IP packet, irrespective of the protocol.
        if(isLimitReached) {
            return TC_ACT_SHOT;
        }
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_UNSPEC;
}



DEFINE_OPTIONAL_BPF_PROG("schedcls/egress/mbb_legacy_swlan", AID_ROOT, AID_NET_ADMIN, sched_cls_egress_mbb_legacy_swlan)
(struct __sk_buff* skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    const int l2_header_size = sizeof(struct ethhdr);

    if (data + l2_header_size + sizeof(struct iphdr) > data_end) {
        return TC_ACT_UNSPEC;
    }

    if(skb->protocol == htons(ETH_P_IP) || skb->protocol == htons(ETH_P_IPV6)) {
        struct ethhdr  *eth  = data;
        int ret = 0;
        uint64_t byte = skb->len;
        bool isLimitReached = 0; // To check if the specific client has reached the limit

        if(skb->protocol == htons(ETH_P_IP)) {
            struct iphdr* ip = (void*)(eth + 1);
            if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
            if (data + sizeof(*eth) + sizeof(*ip) > data_end) return TC_ACT_UNSPEC;
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr* tcph = (void*)(ip + 1);
                if ((data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;

                if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
            }
        } else {
            // Just to keep the loader happy
            if(skb->protocol == htons(ETH_P_IPV6)) {
                struct ipv6hdr* ip6 = (void*)(eth + 1);
                if (eth->h_proto != htons(ETH_P_IPV6)) return TC_ACT_UNSPEC;
                if (data + sizeof(*eth) + sizeof(*ip6) > data_end) return TC_ACT_UNSPEC;
                if (ip6->version != 6) return TC_ACT_UNSPEC;
                if (ip6->nexthdr == IPPROTO_TCP) {
                    struct tcphdr* tcph = (void*)(ip6 + 1);
                    if ((data + sizeof(*eth) + sizeof(*ip6) + sizeof(*tcph)) > data_end)  return TC_ACT_UNSPEC;
                    if (tcph->syn || tcph->fin || tcph->rst) return TC_ACT_UNSPEC;
                }
                // Prevent multicast and broadcast packets from being accounted.
                if (skb->pkt_type != PACKET_HOST) {
                    return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets sourced from ::1 or fe80::/64 or other weirdness.
                __be32 src32 = ip6->saddr.s6_addr32[0];
                if (src32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (src32 & htonl(0xe0000000)) != htonl(0x20000000)) {   // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
                // Protect against forwarding packets destined to ::1 or fe80::/64 or other weirdness.
                __be32 dst32 = ip6->daddr.s6_addr32[0];
                if (dst32 != htonl(0x0064ff9b) &&                        // 64:ff9b:/32 incl. XLAT464 WKP
                   (dst32 & htonl(0xe0000000)) != htonl(0x20000000)) {    // 2000::/3 Global Unicast
                       return TC_ACT_UNSPEC;
                }
            }
        }

        __u32 macpart1 = eth->h_dest[5] | (eth->h_dest[4] << 8) | (eth->h_dest[3] << 16) | (eth->h_dest[2] << 24);
        __u32 macpart2 = eth->h_dest[1] | (eth->h_dest[0] << 8);
        uint64_t key = (((uint64_t)macpart2)<<32) | macpart1;
        /*if (key == 281474976710655 || key == 1101088686331 || key == 1101088686102) {
            return TC_ACT_UNSPEC;
        }*/ //TODO:
        if(skb->protocol == htons(ETH_P_IP)) {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IP_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV4_TCP_SIZE))
                    isLimitReached = 1;
            }
        } else {
            uint8_t proto;
            ret = bpf_skb_load_bytes(skb, ETH_HLEN + IPV6_PROTO_OFF, &proto, 1);
            if (!ret && proto == IPPROTO_UDP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            } else if (!ret && proto == IPPROTO_TCP) {
                if(pause_or_update_datausage(key, byte, IPV6_TCP_SIZE))
                    isLimitReached = 1;
            }
        }
        // We drop any IP packet, irrespective of the protocol.
        if(isLimitReached) {
            return TC_ACT_SHOT;
        }
        return TC_ACT_UNSPEC;
    }
    return TC_ACT_UNSPEC;
}

// S-HS : END >
//#endif

LICENSE("Apache 2.0");
CRITICAL("Sem eBPF Smart Hotspot");