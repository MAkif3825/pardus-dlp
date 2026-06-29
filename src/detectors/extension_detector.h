#ifndef _DETECTORS_EXTENSION_DETECTOR_H_
#define _DETECTORS_EXTENSION_DETECTOR_H_

#include <bpf/libbpf.h>

struct extension_config {
	const char* db_path;
	struct bpf_map* ext_map;
};

#endif /* !_DETECTORS_EXTENSION_DETECTOR_H_ */