#ifndef _KERNEL_PARDUS_DLP_H_
#define _KERNEL_PARDUS_DLP_H_

#define DLP_COMM_LEN 16
#define DLP_FILENAME_LEN 512

/* --- Core Identifiers --- */
#define SUBJECT_TYPE_UID 1
#define SUBJECT_TYPE_GID 2
#define SUBJECT_TYPE_ALL 3

/* --- Universal Access Mask (UAM) --- */
/* Combinations: 7=Full, 6=R/W, 5=R/X, 4=Read-Only, 0=Lockout */
#define UAM_READ 4
#define UAM_WRITE 2
#define UAM_EXEC 1

/* --- Polymorphic Rule Methods --- */
#define RULE_TYPE_PERM 1
#define RULE_TYPE_TIME 2
#define RULE_TYPE_APP 3
#define RULE_TYPE_SESSION 4
#define RULE_TYPE_RATE 5
#define RULE_TYPE_EXT 6
#define RULE_TYPE_IP 7
#define RULE_TYPE_AUDIT 8

/* --- Map Key Structure --- */
struct access_policy_key {
	unsigned long long dir_inode;
	unsigned int subject_id;
	unsigned int subject_type;
};

/* --- Polymorphic Map Value Structure --- */
struct access_policy_value {
	unsigned int rule_type; /* Identifies the method (1-8) */
	unsigned int _padding_hdr; /* 8-byte boundary alignment for verifier */

	union {
		struct {
			unsigned char perm_mask;
		} perm;

		struct {
			unsigned char start_hour;
			unsigned char end_hour;
			unsigned char work_mask;
			unsigned char off_mask;
		} time;

		struct {
			char trusted_comm[DLP_COMM_LEN];
			unsigned char perm_mask;
		} app;

		struct {
			unsigned char is_remote; /* 0 = LOCAL, 1 = REMOTE */
			unsigned char perm_mask;
		} session;

		struct {
			unsigned int max_rpm;
		} rate;

		struct {
			char allowed_ext[8]; /* e.g., ".pdf" */
			unsigned char perm_mask;
		} ext;

		struct {
			unsigned int subnet_ip;
			unsigned int subnet_mask;
			unsigned char perm_mask;
		} ip;

		struct {
			unsigned char audit_mask; /* Uses UAM to determine what to log */
		} audit;
	} payload;
};

/* --- Existing Engine Contracts --- */
struct dlp_event {
	char full_path[DLP_FILENAME_LEN];
	char comm[DLP_COMM_LEN];
	unsigned int flags;
	unsigned int pid;
	unsigned int uid;
};

#ifndef O_ACCMODE
#define O_ACCMODE 3
#define O_RDONLY 0
#define O_WRONLY (1 << 0)
#define O_RDWR (1 << 1)
#endif

#endif /* !_KERNEL_PARDUS_DLP_H_ */