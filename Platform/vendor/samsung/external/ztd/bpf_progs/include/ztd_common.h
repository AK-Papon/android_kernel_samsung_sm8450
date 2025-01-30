
#ifndef ZTD_COMMON_H
#define ZTD_COMMON_H

#define BPF_FS_PATH "/sys/fs/bpf/"

#define SHARED_OBJ  ""
#define PROG_(name) "prog_" name "_"
#define MAP_(name)  "map_"  name "_"

#define SCHEDCLS_   "schedcls_"
#define TRACEPOINT_ "tracepoint_"
#define KPROBE_     "kprobe_"

// Configurations
#define USE_RINGBUF 1
#define DEFAULT_RINGBUF_TIMEOUT (-1)

#ifndef MAX_TASK_COMM_LEN
#define MAX_TASK_COMM_LEN 16
#endif

/*
 * The following Definitions must be synchronized with
 * the com.samsung.android.knox.zt.devicetrust.EndpointMonitorConst class
 */
static const int GENERIC_SYSCALL_NR_OPEN   = 56;
static const int GENERIC_SYSCALL_NR_CLOSE  = 57;
static const int GENERIC_SYSCALL_NR_MOUNT  = 40;
static const int GENERIC_SYSCALL_NR_EXECVE = 221;

static const int FLAG_TRACING_FS        = 0x01;
static const int FLAG_TRACING_SC_OPEN   = 0x02;
static const int FLAG_TRACING_SC_CLOSE  = 0x04;
static const int FLAG_TRACING_SC_MOUNT  = 0x08;
static const int FLAG_TRACING_SC_EXECVE = 0x10;
static const int FLAG_TRACING_SK        = 0x20;
static const int FLAG_TRACING_PKT       = 0x40;

// Trace Classification
static const int TRACE_CLASS_FILE_ACCESS   = 1;
static const int TRACE_CLASS_DOMAIN_ACCESS = 2;

// Trace Types that Ztd Supports
static const int TRACE_TYPE_SYSCALL = 1;
static const int TRACE_TYPE_FS      = 2;
static const int TRACE_TYPE_SOCK    = 3;
static const int TRACE_TYPE_PROC    = 4;
static const int TRACE_TYPE_PKT     = 5;
static const int TRACE_TYPE_DOMAIN  = 6;

// Sub-systems of Tracepoint
static const int TRACE_SYSTEM_RAW_SYSCALL = 1;
static const int TRACE_SYSTEM_F2FS        = 2;
static const int TRACE_SYSTEM_SOCK        = 3;
static const int TRACE_SYSTEM_SCHED       = 4;
static const int TRACE_SYSTEM_ETC         = 5;

// Events of SC(System Call) trace
static const int TRACE_EVENT_SYS_ENTER            = 101;
static const int TRACE_EVENT_SYS_EXIT             = 102;
static const int TRACE_EVENT_SYS_OPEN             = 103;
static const int TRACE_EVENT_SYS_CLOSE            = 104;
static const int TRACE_EVENT_SYS_MOUNT            = 105;
static const int TRACE_EVENT_SYS_EXECVE           = 106;

// Events of FS(File System) Trace
static const int TRACE_EVENT_F2FS_IGET            = 201;
static const int TRACE_EVENT_F2FS_IGET_EXIT       = 202;
static const int TRACE_EVENT_F2FS_READDIR         = 203;
static const int TRACE_EVENT_F2FS_READPAGE        = 204;
static const int TRACE_EVENT_F2FS_READPAGES       = 205;
static const int TRACE_EVENT_F2FS_UNLINK_ENTER    = 206;
static const int TRACE_EVENT_F2FS_UNLINK_EXIT     = 207;
static const int TRACE_EVENT_F2FS_WRITEPAGE       = 208;
static const int TRACE_EVENT_F2FS_WRITEPAGES      = 209;
static const int TRACE_EVENT_F2FS_DATAREAD_START  = 210;
static const int TRACE_EVENT_F2FS_DATAREAD_END    = 211;
static const int TRACE_EVENT_F2FS_DATAWRITE_START = 212;
static const int TRACE_EVENT_F2FS_DATAWRITE_END   = 213;

// Events of SK(Socket) Trace
static const int TRACE_EVENT_INET_SOCK_SET_STATE  = 301;

// Events of PK(Packet) Trace
static const int TRACE_EVENT_SCHED_CLS_INGRESS    = 501;
static const int TRACE_EVENT_SCHED_CLS_EGRESS     = 502;

typedef struct tp_base_data {
    uint64_t event_time;
    uint64_t pid_tgid;
    uint64_t uid_gid;
    char comm[MAX_TASK_COMM_LEN];
} tp_base_data_t;

#endif // ZTD_COMMON_H
