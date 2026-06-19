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

SEC("tracepoint/syscalls/sys_enter_openat")
int dlp_handle_openat(struct trace_event_raw_sys_enter *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    
    // Ignore events originating from our own DLP agent process
    if (pid == my_pid)
        return 0;

    // Reserve an event block safely inside the lockless ring buffer
    struct dlp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid     = pid;
    e->uid     = (__u32)bpf_get_current_uid_gid();
    e->op_type = DLP_OP_OPEN;
    e->flags   = ctx->args[2]; // Fixed: Matches the header mapping perfectly

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Safely copy string from user-space address space into kernel memory
    if (bpf_probe_read_user_str(&e->filename, sizeof(e->filename),
                                 (const char *)ctx->args[1]) < 0) {
        e->filename[0] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}