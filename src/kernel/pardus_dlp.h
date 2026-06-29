#pragma once

#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 512

struct dlp_event {
	unsigned int pid;
	unsigned int uid;
	unsigned int flags;
	char comm[TASK_COMM_LEN];
	char full_path[MAX_FILENAME_LEN];
};

#ifndef O_ACCMODE
#define O_ACCMODE 3
#define O_RDONLY  0
#define O_WRONLY  (1 << 0)
#define O_RDWR	  (1 << 1)
#endif
