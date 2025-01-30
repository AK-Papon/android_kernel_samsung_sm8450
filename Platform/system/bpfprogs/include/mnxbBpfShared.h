#pragma once

// This header file is shared by eBPF kernel programs (C) and netd (C++) and
// some of the maps are also accessed directly from Java mainline module code.
//
// Hence: explicitly pad all relevant structures and assert that their size
// is the sum of the sizes of their fields.
#define STRUCT_SIZE(name, size) _Static_assert(sizeof(name) == (size), "Incorrect struct size.")

#define ADV_WINDOW_WRITE_INDEX   1

#define KEY_STAT_TCP_RX 60
#define KEY_STAT_TCP_TX 61
#define KEY_STAT_UDP_RX 170
#define KEY_STAT_UDP_TX 171

const int MNXB_UID_OWNER_MAP_SIZE = 1024;

#define MNXB_BPF_PATH "/sys/fs/bpf/"

// Programs
#define MNXB_INGRESS_ETHER_PROG_PATH MNXB_BPF_PATH "prog_mnxbNetd_schedcls_ingress_mnxb_ether"
#define MNXB_EGRESS_ETHER_PROG_PATH MNXB_BPF_PATH "prog_mnxbNetd_schedcls_egress_mnxb_ether"

// Maps
// Priority map
#define MNXB_UID_OWNER_MAP MNXB_BPF_PATH "map_mnxbNetd_mnxb_uid_owner_map"
#define MNXB_UID_DEST6_MAP_PATH MNXB_BPF_PATH "map_mnxbNetd_mnxb_uid_dest6_map"
#define MNXB_ADV_WINDOW_MAP MNXB_BPF_PATH "map_mnxbNetd_mnxb_adv_window_map"
#define MNXB_L4_STATS_MAP_PATH MNXB_BPF_PATH "map_mnxbNetd_mnxb_l4_stats_map"

enum MnxbUidOwnerMatchType {
    MNXB_BPF_MATCH = (1 << 0),
};

typedef struct {
    // Allowed interface index. Only applicable if IIF_MATCH is set in the rule bitmask above.
    uint32_t iif;
    // A bitmask of enum values in UidOwnerMatchType.
    //uint8_t is full ,add to 32bit
    uint32_t rule;
} MnxbUidOwnerValue;
STRUCT_SIZE(MnxbUidOwnerValue, 2 * 4);  // 8

#undef STRUCT_SIZE
