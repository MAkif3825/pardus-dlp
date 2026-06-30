#ifndef _DETECTORS_ACCESS_DETECTOR_H_
#define _DETECTORS_ACCESS_DETECTOR_H_

#include "detector.h"
#include <bpf/libbpf.h>

/* * The configuration payload passed to access_init() by main.c
 */
struct access_config {
	const char* db_path;
	struct bpf_map* stage1_map; /* The Inode pre-filter map */
	struct bpf_map* stage2_map; /* The full constraint matrix map */
};

/* * Expose the global detector instance so main.c can register it.
 */
extern struct detector access_detector;

#endif /* !_DETECTORS_ACCESS_DETECTOR_H_ */