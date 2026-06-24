#include "dispatch.h"
#include "utils/alert.h"
#include "detectors/detector.h"

extern detector_t policy_detector;
extern detector_t malware_detector; 

static detector_t *detectors[] = {
    &policy_detector,
    &malware_detector,            
    NULL // Null-terminator simplifies loop counting
};

int handle_event(void *ctx, void *data, size_t data_sz) {
    if (!data || data_sz < sizeof(struct dlp_event)) return 0;
    
    const struct dlp_event *raw = data;
    char reason[256];

    for (int i = 0; detectors[i] != NULL; i++) {
        if (!detectors[i] || !detectors[i]->handle) {
            continue;
        }

        detection_result_t result = detectors[i]->handle(raw, reason, sizeof(reason));
        
        if (result == DETECTION_ALERT) {
            alert_report(detectors[i]->name, raw, reason);
        }
    }

    return 0;
}