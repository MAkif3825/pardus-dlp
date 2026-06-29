#ifndef _KERNEL_PARDUS_DLP_H_
#define _KERNEL_PARDUS_DLP_H_

#define DLP_COMM_LEN 16
#define DLP_FILENAME_LEN 512

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