/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H


#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
};

// Enumeration for op_type value in dlp_event  
enum dlp_op_type {
	DLP_OP_OPEN = 1,
	DLP_OP_WRITE = 2,
	DLP_OP_CLOSE = 3
};

// Data type used to transfer information to user-space
struct dlp_event {
	__u32 pid;
	__u32 uid;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	__u32 op_type;
};

#endif /* __BOOTSTRAP_H */
