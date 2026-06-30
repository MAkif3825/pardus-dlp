#ifndef _KERNEL_PARDUS_DLP_H_
#define _KERNEL_PARDUS_DLP_H_

#define DLP_COMM_LEN 16
#define DLP_FILENAME_LEN 512

/* --- Access Engine Contracts --- */
#define SUBJECT_TYPE_UID 1
#define SUBJECT_TYPE_GID 2

/* Extensible Feature Bitmasks */
#define MODULE_TIME (1 << 0)
#define MODULE_OP_TYPE (1 << 1)

struct access_policy_key {
	unsigned long long dir_inode; /* Universally valid 64-bit integer */
	unsigned int subject_id; /* Universally valid 32-bit integer */
	unsigned int subject_type; /* Universally valid 32-bit integer */
};

struct access_policy_value {
	unsigned int enabled_modules;
	unsigned char start_hour; /* Universally valid 8-bit integer */
	unsigned char end_hour; /* Universally valid 8-bit integer */
	unsigned char allow_write; /* Universally valid 8-bit integer */
	unsigned char _padding; /* Explicit verifier alignment padding */
};

/* --- Existing Engine Contracts --- */
struct dlp_event {
	char full_path[DLP_FILENAME_LEN]; /* 512 bytes */
	char comm[DLP_COMM_LEN]; /* 16 bytes */
	unsigned int flags; /* 4 bytes */
	unsigned int pid; /* 4 bytes */
	unsigned int uid; /* 4 bytes */
};

#ifndef O_ACCMODE
#define O_ACCMODE 3
#define O_RDONLY 0
#define O_WRONLY (1 << 0)
#define O_RDWR (1 << 1)
#endif

#endif /* !_KERNEL_PARDUS_DLP_H_ */