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

static __always_inline bool is_access_blocked(unsigned char active_mask, unsigned int flags)
{
	/* Total Lockout check */
	if (active_mask == 0)
		return true;

	/* Check Read Intent (cat, cp, O_RDONLY) */
	if (flags == O_RDONLY || flags == O_RDWR) {
		if (!(active_mask & 4))
			return true; /* Blocked: Missing Read (4) bit */
	}

	/* Check Write Intent (echo, modify, O_WRONLY) */
	if (flags == O_WRONLY || flags == O_RDWR) {
		if (!(active_mask & 2))
			return true; /* Blocked: Missing Write (2) bit */
	}

	return false; /* Passed all checks */
}

/* Helper to check if Execution (Bit 1) is blocked */
static __always_inline bool is_exec_blocked(unsigned char active_mask)
{
	/* Total Lockout check */
	if (active_mask == 0)
		return true;

	/* Check Execute Intent: Does the mask lack the 1 bit? */
	if (!(active_mask & 1))
		return true;

	return false;
}

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

	/* 3. Stage 2 Lookup: Check UID */
	pkey.dir_inode = dir_inode;
	pkey.subject_id = uid;
	pkey.subject_type = SUBJECT_TYPE_UID;
	rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);

	/* Fallback 1: Check GID */
	if (!rule) {
		pkey.subject_id = gid;
		pkey.subject_type = SUBJECT_TYPE_GID;
		rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);
	}

	/* Fallback 2: Check ALL (Global Net) */
	if (!rule) {
		pkey.subject_id = 0; /* ID doesn't matter for ALL */
		pkey.subject_type = SUBJECT_TYPE_ALL;
		rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);
	}

	/* 4. Execute the Polymorphic Policy Matrix */
	if (rule) {
		unsigned int flags = file->f_flags & O_ACCMODE;

		switch (rule->rule_type) {

		case RULE_TYPE_PERM:
			is_blocked = is_access_blocked(rule->payload.perm.perm_mask, flags);
			break;

		case RULE_TYPE_TIME: {
			__u64 tai_ns = bpf_ktime_get_tai_ns();
			__u32 current_hour = (tai_ns / 1000000000ULL / 3600ULL) % 24ULL;

			bool within_window = false;
			__u8 active_mask = rule->payload.time.off_mask;

			if (rule->payload.time.start_hour != rule->payload.time.end_hour) {
				if (rule->payload.time.start_hour > rule->payload.time.end_hour) {
					if (current_hour >= rule->payload.time.start_hour || current_hour < rule->payload.time.end_hour)
						within_window = true;
				} else {
					if (current_hour >= rule->payload.time.start_hour && current_hour < rule->payload.time.end_hour)
						within_window = true;
				}
			}

			if (within_window) {
				active_mask = rule->payload.time.work_mask;
			}

			/* Evaluate the calculated mask via UAM standard */
			is_blocked = is_access_blocked(active_mask, flags);
			break;
		}

		case RULE_TYPE_APP:
		case RULE_TYPE_SESSION:
		case RULE_TYPE_RATE:
		case RULE_TYPE_EXT:
		case RULE_TYPE_AUDIT:
			/* Ready for your extensions tomorrow! */
			break;
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
	struct dlp_event* e;
	__u64 pid_tgid;
	pid_t pid;
	__u32 uid, gid;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid & 0xFFFFFFFF;

	/* Ignore our own agent */
	if (pid == my_pid)
		return (0);

	uid = (bpf_get_current_uid_gid() & 0xFFFFFFFF);

	/* =========================================================================
	 * PHASE 1: GLOBAL EXTENSION BLOCKER (Your existing logic)
	 * ========================================================================= */
	char fname[128];
	char lookup_key[8] = { 0 };
	const char* filename = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(fname, sizeof(fname), filename);

	int len = 0, ext_idx = -1;
	for (int i = 0; i < 128; i++) {
		if (fname[i] == '\0') {
			len = i;
			break;
		}
	}

	for (int k = 1; k <= 16; k++) {
		int check_idx = len - k;
		if (check_idx < 0)
			break;
		if (fname[check_idx] == '.') {
			ext_idx = check_idx + 1;
			break;
		}
	}

	if (ext_idx > 0 && ext_idx < 128) {
		for (int j = 0; j < 7; j++) {
			int target_idx = ext_idx + j;
			if (target_idx >= 128 || fname[target_idx] == '\0')
				break;
			lookup_key[j] = fname[target_idx];
		}

		__u32* allowed = bpf_map_lookup_elem(&extensions, lookup_key);
		if (allowed != NULL) {
			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
			if (e != NULL) {
				e->pid = pid;
				e->uid = uid;
				e->flags = 0xDEAD; /* Extension Block Flag */
				bpf_get_current_comm(&e->comm, sizeof(e->comm));
				bpf_probe_read_kernel_str(e->full_path, sizeof(e->full_path), filename);
				bpf_ringbuf_submit(e, 0);
			}
			return (-13); /* Drop hammer on extension */
		}
	}

	/* =========================================================================
	 * PHASE 2: POLYMORPHIC UAM POLICY (Directory-Specific)
	 * ========================================================================= */
	struct file* file = BPF_CORE_READ(bprm, file);
	if (!file)
		return (0);

	struct inode* parent_inode = BPF_CORE_READ(file, f_path.dentry, d_parent, d_inode);
	if (!parent_inode)
		return (0);

	__u64 dir_inode = BPF_CORE_READ(parent_inode, i_ino);
	__u32* is_monitored = bpf_map_lookup_elem(&stage1_inode_map, &dir_inode);

	/* If directory isn't monitored by access.csv, exit successfully */
	if (!is_monitored)
		return (0);

	struct access_policy_key pkey = { 0 };
	struct access_policy_value* rule;

	/* Stage 2 Lookup: Check UID */
	pkey.dir_inode = dir_inode;
	pkey.subject_id = uid;
	pkey.subject_type = SUBJECT_TYPE_UID;
	rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);

	/* Fallback 1: Check GID */
	if (!rule) {
		pkey.subject_id = gid;
		pkey.subject_type = SUBJECT_TYPE_GID;
		rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);
	}

	/* Fallback 2: Check ALL (Global Net) */
	if (!rule) {
		pkey.subject_id = 0; /* ID doesn't matter for ALL */
		pkey.subject_type = SUBJECT_TYPE_ALL;
		rule = bpf_map_lookup_elem(&stage2_policy_map, &pkey);
	}

	if (rule) {
		bool is_blocked = false;

		switch (rule->rule_type) {
		case RULE_TYPE_PERM:
			is_blocked = is_exec_blocked(rule->payload.perm.perm_mask);
			break;
		case RULE_TYPE_TIME: {
			unsigned long long tai_ns = bpf_ktime_get_tai_ns();
			unsigned int current_hour = (tai_ns / 1000000000ULL / 3600ULL) % 24ULL;
			bool within_window = false;
			unsigned char active_mask = rule->payload.time.off_mask;

			if (rule->payload.time.start_hour != rule->payload.time.end_hour) {
				if (rule->payload.time.start_hour > rule->payload.time.end_hour) {
					if (current_hour >= rule->payload.time.start_hour || current_hour < rule->payload.time.end_hour)
						within_window = true;
				} else {
					if (current_hour >= rule->payload.time.start_hour && current_hour < rule->payload.time.end_hour)
						within_window = true;
				}
			}
			if (within_window)
				active_mask = rule->payload.time.work_mask;

			is_blocked = is_exec_blocked(active_mask);
			break;
		}
		}

		if (is_blocked) {
			e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
			if (e != NULL) {
				e->pid = pid;
				e->uid = uid;
				e->flags = 0xECEE; /* UAM Policy Exec Block Flag */
				bpf_get_current_comm(&e->comm, sizeof(e->comm));
				bpf_probe_read_kernel_str(e->full_path, sizeof(e->full_path), filename);
				bpf_ringbuf_submit(e, 0);
			}
			return (-13); /* Drop hammer on policy */
		}
	}

	return (0);
}