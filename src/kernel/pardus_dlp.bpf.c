#include "pardus_dlp.h"
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* ---------------- MAP DEFINITIONS ---------------- */

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

/* Stage 1: The Fast-Path Inode Filter */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u32);
} stage1_inode_map SEC(".maps");

/* Stage 2: The Complex Constraint Matrix */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct access_policy_key);
	__type(value, struct access_policy_value);
} stage2_policy_map SEC(".maps");

const volatile int my_pid = 0;

/* ---------------- FILE ACCESS ENGINE ---------------- */

SEC("lsm/file_open")
int BPF_PROG(dlp_file_open, struct file* file)
{
	struct dlp_event* e;
	struct inode* parent_inode;
	struct access_policy_key pkey = { 0 };
	struct access_policy_value* rule;
	__u64 pid_tgid, uid_gid, dir_inode;
	__u32 uid, gid, *is_monitored;
	pid_t pid;
	bool is_blocked = false;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid & 0xFFFFFFFF;

	if (pid == my_pid)
		return (0);

	/* 1. Fast-Path Pre-Filter: Check if directory is monitored */
	parent_inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode);
	if (!parent_inode)
		return (0);

	dir_inode = BPF_CORE_READ(parent_inode, i_ino);
	is_monitored = bpf_map_lookup_elem(&stage1_inode_map, &dir_inode);

	/* If directory is not in the CSV policy, allow instantly. Zero overhead. */
	if (!is_monitored)
		return (0);

	/* 2. Context Extraction */
	uid_gid = bpf_get_current_uid_gid();
	uid = uid_gid & 0xFFFFFFFF;
	gid = uid_gid >> 32;

	/* 3. Stage 2 Lookup: Check UID specific rules first */
	pkey.dir_inode = dir_inode;
	pkey.subject_id = uid;
	pkey.subject_type = SUBJECT_TYPE_UID;
	rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);

	/* Fallback: Check GID rules if no specific UID rule exists */
	if (!rule) {
		pkey.subject_id = gid;
		pkey.subject_type = SUBJECT_TYPE_GID;
		rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);
	}

	/* 4. Execute the Bitmask Checklist Matrix */
	if (rule) {
		/* Evaluate Operation Module (Read vs Write) */
		if (rule->enabled_modules & MODULE_OP_TYPE) {
			if (!rule->allow_write) {
				unsigned int flags = file->f_flags & O_ACCMODE;
				if (flags == O_WRONLY || flags == O_RDWR)
					is_blocked = true;
			}
		}

		/* Evaluate Time Boundaries Module */
		if (!is_blocked && (rule->enabled_modules & MODULE_TIME)) {
			__u64 tai_ns = bpf_ktime_get_tai_ns();
			/* Convert UTC Epoch Nanoseconds to Hour of the day (0-23) */
			__u32 current_hour = (tai_ns / 1000000000ULL / 3600ULL) % 24ULL;

			/* Default to true. We only block if a set rule is actively violated. */
			bool within_window = true;

			/* Only run checks if the hours are actually configured differently */
			if (rule->start_hour != rule->end_hour) {
				within_window = false;

				if (rule->start_hour > rule->end_hour) {
					/* Overnight shifts (e.g., 18:00 to 08:00) */
					if (current_hour >= rule->start_hour || current_hour < rule->end_hour)
						within_window = true;
				} else {
					/* Standard shifts (e.g., 09:00 to 17:00) */
					if (current_hour >= rule->start_hour && current_hour < rule->end_hour)
						within_window = true;
				}
			}

			if (!within_window)
				is_blocked = true;
		}
	}

	/* 5. Telemetry & Enforcement Generation */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (e != NULL) {
		e->pid = pid;
		e->uid = uid;

		if (is_blocked)
			e->flags = 0xBADF; /* Specific trigger for access_detector.c */
		else
			e->flags = file->f_flags; /* Audit pass-through for monitored folders */

		bpf_get_current_comm(&e->comm, sizeof(e->comm));
		bpf_d_path(&file->f_path, e->full_path, sizeof(e->full_path));
		bpf_ringbuf_submit(e, 0);
	}

	if (is_blocked)
		return (-13); /* -EACCES: Block Operation */

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