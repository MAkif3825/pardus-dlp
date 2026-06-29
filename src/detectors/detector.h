#ifndef _DETECTORS_DETECTOR_H_
#define _DETECTORS_DETECTOR_H_

#include <stddef.h>

#include "kernel/pardus_dlp.h"

enum detection_result { DETECTION_PASS = 0,
	DETECTION_ALERT = 1,
	DETECTION_ERROR = -1 };

struct detector {
	const char* name;
	int (*init)(void* config);
	enum detection_result (*handle)(
	    const struct dlp_event* e, char* reason_out, size_t reason_len);
	void (*destroy)(void);
};

#endif /* !_DETECTORS_DETECTOR_H_ */