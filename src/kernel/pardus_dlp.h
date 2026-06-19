#pragma once

#define TASK_COMM_LEN    16
#define MAX_FILENAME_LEN 512   

typedef enum {
    DLP_OP_OPEN  = 1,
    DLP_OP_WRITE = 2,
    DLP_OP_CLOSE = 3,
} dlp_op_type_t;

struct dlp_event {
    unsigned int pid;
    unsigned int uid;
    unsigned int op_type;   // dlp_op_type_t
    unsigned int flags;     
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

