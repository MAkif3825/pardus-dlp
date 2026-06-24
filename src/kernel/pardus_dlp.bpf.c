#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pardus_dlp.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile int my_pid = 0;

SEC("lsm/file_open")
int BPF_PROG(dlp_file_open, struct file *file)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    pid_t pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    long path_len;

    // Ignore events originating from our own DLP agent process
    if (pid == my_pid)
        return 0;

    // Reserve an event block safely inside the lockless ring buffer
    struct dlp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid     = pid;
    e->uid     = bpf_get_current_uid_gid() & 0xFFFFFFFF;;
    e->flags   = file->f_flags;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Execute the kernel-side path resolution
    path_len = bpf_d_path(&file->f_path, e->full_path, sizeof(e->full_path));
    if (path_len < 0) {
        // The path is invalid or can't be resolved. Release the memory block.
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}