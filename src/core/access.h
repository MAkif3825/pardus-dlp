#ifndef PARDUS_DLP_ACCESS_H
#define PARDUS_DLP_ACCESS_H

#include "../kernel/pardus_dlp.h"
#include <linux/types.h>

/* Function Prototypes for User-Space */
int access_db_init(const char* db_path, int stage1_map_fd, int stage2_map_fd);

#endif /* PARDUS_DLP_ACCESS_H */