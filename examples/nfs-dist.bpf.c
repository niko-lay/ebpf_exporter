#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#define MAX_ENTRIES 10240

#define MAX_LATENCY_SLOT 27

enum fs_file_op {
    F_READ,
    F_WRITE,
    F_OPEN,
    F_FSYNC,
    F_UNLINK,
    F_GETATTR,
    F_MKDIR,
    
    F_MAX
};

struct nfs_latency_key_t {
    u8 op;
    u8 bucket;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, u64);
} nfs_evt_storage SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, (MAX_LATENCY_SLOT + 1) * F_MAX);
    __type(key, struct nfs_latency_key_t);
    __type(value, u64);
} nfs_latency_seconds SEC(".maps");

static int probe_entry()
{
    u32 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    bpf_map_update_elem(&nfs_evt_storage, &pid, &ts, BPF_ANY);

    return 0;
}

static int probe_return(enum fs_file_op op)
{
    u64 *tsp, delta_us, ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    struct nfs_latency_key_t key = { .op = (u8) op };

    tsp = bpf_map_lookup_elem(&nfs_evt_storage, &pid);
    if (!tsp) {
        return 0;
    }

    delta_us = (ts - *tsp) / 1000;

    increment_exp2_histogram(&nfs_latency_seconds, key, delta_us, MAX_LATENCY_SLOT);

    bpf_map_delete_elem(&nfs_evt_storage, &pid);

    return 0;
}

// read
SEC("fentry/nfs_file_read")
int BPF_PROG(nfs_file_read, struct kiocb *iocb) {
    return probe_entry();
}

SEC("fexit/nfs_file_read")
int BPF_PROG(nfs_file_read_ret, ssize_t ret) {
    return probe_return(F_READ);
}

// write
SEC("fentry/nfs_file_write")
int BPF_PROG(nfs_file_write, struct kiocb *iocb) {
    return probe_entry();
}

SEC("fexit/nfs_file_write")
int BPF_PROG(nfs_file_write_ret, ssize_t ret) {
    return probe_return(F_WRITE);
}

// open
SEC("fentry/nfs_file_open")
int BPF_PROG(nfs_file_open, struct inode *inode, struct file *filp) {
    return probe_entry();
}

SEC("fexit/nfs_file_open")
int BPF_PROG(nfs_file_open_ret, ssize_t ret) {
    return probe_return(F_OPEN);
}

// SEC("fentry/nfs4_file_open")
// int BPF_PROG(nfs4_file_open, struct inode *inode, struct file *filp) {
//     return probe_entry();
// }

// SEC("fexit/nfs4_file_open")
// int BPF_PROG(nfs4_file_open_ret, ssize_t ret) {
//     return probe_return(F_OPEN);
// }

// don't fail to load exporter if target functions are missing in the kernel
SEC("kprobe/nfs4_file_open")
int BPF_KPROBE(nfs4_file_open, struct inode *inode, struct file *filp) {
    return probe_entry();
}

SEC("kretprobe/nfs4_file_open")
int BPF_KRETPROBE(nfs4_file_open_ret, ssize_t ret) {
    return probe_return(F_OPEN);
}


// fsync
SEC("fentry/nfs_file_fsync")
int BPF_PROG(nfs_file_fsync, struct file *file) {
    return probe_entry();
}

SEC("fexit/nfs_file_fsync")
int BPF_PROG(nfs_file_fsync_ret, ssize_t ret) {
    return probe_return(F_FSYNC);
}

// unlink
SEC("fentry/nfs_unlink")
int BPF_PROG(nfs_unlink, struct inode *dir, struct dentry *dentry) {
    return probe_entry();
}

SEC("fexit/nfs_unlink")
int BPF_PROG(nfs_unlink_ret, ssize_t ret) {
    return probe_return(F_UNLINK);
}

// getattr
SEC("fentry/nfs_getattr")
int BPF_PROG(nfs_getattr) {
    return probe_entry();
}

SEC("fexit/nfs_getattr")
int BPF_PROG(nfs_getattr_ret, ssize_t ret) {
    return probe_return(F_GETATTR);
}

// mkdir
SEC("fentry/nfs_mkdir")
int BPF_PROG(nfs_mkdir, struct mnt_idmap *idmap) {
    return probe_entry();
}

SEC("fexit/nfs_mkdir")
int BPF_PROG(nfs_mkdir_ret, ssize_t ret) {
    return probe_return(F_MKDIR);
}

char LICENSE[] SEC("license") = "GPL";
