#include "pardus_dlp.h"
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32);
	__type(key, char[8]);
	__type(value, int);
} extensions SEC(".maps");

const volatile int my_pid = 0;

SEC("lsm/file_open")
int BPF_PROG(dlp_file_open, struct file* file)
{
	struct dlp_event* e;
	__u64 pid_tgid;
	long path_len;
	pid_t pid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

	/* Ignore events originating from our own DLP agent process. */
	if (pid == my_pid)
		return (0);

	/* Reserve an event block safely inside the lockless ring buffer. */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e == NULL)
		return (0);

	e->pid = pid;
	e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	e->flags = file->f_flags;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Execute the kernel-side path resolution. */
	path_len = bpf_d_path(&file->f_path, e->full_path, sizeof(e->full_path));
	if (path_len < 0) {
		/* The path is invalid. Release the memory block. */
		bpf_ringbuf_discard(e, 0);
		return (0);
	}

	bpf_ringbuf_submit(e, 0);
	return (0);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(dlp_bprm_check, struct linux_binprm* bprm)
{
	char fname[128];
	char lookup_key[8] = { 0 };
	struct dlp_event* e;
	const char* filename;
	__u32* allowed;
	__u64 pid_tgid;
	pid_t pid;
	int check_idx;
	int ext_idx;
	int i;
	int j;
	int k;
	int len;
	int target_idx;
	char c;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid & 0xFFFFFFFF;

	/* Ignore events originating from our own DLP agent process. */
	if (pid == my_pid)
		return (0);

	filename = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(fname, sizeof(fname), filename);

	ext_idx = -1;
	len = 0;

	/* 1. Locate the true length of the string dynamically (Max 128) */
	for (i = 0; i < 128; i++) {
		if (fname[i] == '\0') {
			len = i;
			break;
		}
	}

	/*
	 * 2. Scan backward from the end of the string to find the last dot
	 * safely. Looking backward up to 16 characters catches extensions
	 * while satisfying the verifier.
	 */
	for (k = 1; k <= 16; k++) {
		check_idx = len - k;

		if (check_idx < 0)
			break;

		if (fname[check_idx] == '.') {
			ext_idx = check_idx + 1;
			break; /* Found the trailing extension delimiter! */
		}
	}

	/*
	 * 3. If a dot was found within safe string boundaries, perform the
	 * isolated extraction.
	 */
	if (ext_idx > 0 && ext_idx < 128) {
		/* Copy up to 7 characters into our isolated lookup key buffer.
		 */
		for (j = 0; j < 7; j++) {
			target_idx = ext_idx + j;

			/* Boundary fallback protection to satisfy verifier. */
			if (target_idx >= 128)
				break;

			c = fname[target_idx];
			if (c == '\0')
				break;

			lookup_key[j] = c;
		}

		/* 4. Query our hash map using the safely structured key. */
		allowed = bpf_map_lookup_elem(&extensions, lookup_key);

		if (allowed != NULL) {
			/* Allocate an event payload inside your ring buffer.
			 */
			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
			if (e != NULL) {
				e->pid = pid;
				e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
				e->flags = 0xDEAD; /* Blocked flag to userspace */

				bpf_get_current_comm(&e->comm, sizeof(e->comm));
				bpf_probe_read_kernel_str(
				    e->full_path, sizeof(e->full_path), filename);

				bpf_ringbuf_submit(e, 0);
			}

			/* Drop the hammer inline! */
			return (-13); /* -EACCES (Permission Denied) */
		}
	}

	return (0);
}