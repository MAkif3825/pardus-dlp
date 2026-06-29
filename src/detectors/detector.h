#pragma once
#include "kernel/pardus_dlp.h"
#include <stddef.h>

typedef enum {
	DETECTION_PASS	= 0,
	DETECTION_ALERT = 1,
	DETECTION_ERROR = -1,
} detection_result_t;

typedef struct {
	const char *name;
	int (*init)(void *config);
	detection_result_t (*handle)(const struct dlp_event *e,
				     char *reason_out, size_t reason_len);
	void (*destroy)(void);
} detector_t;