#ifndef _EVENT_H_
#define _EVENT_H_

#include "kernel/pardus_dlp.h"

struct enriched_event {
	char resolved_path[4096];
	const struct dlp_event* raw;
};

#endif /* !_EVENT_H_ */