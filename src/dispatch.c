#include "dispatch.h"
#include "utils/event_utils.h"
#include "utils/alert.h"
#include "detectors/detector.h"

// Forward declare the plugin instance defined in policy_detector.c
extern detector_t policy_detector;

// An array pointing to our active security modules
static detector_t *detectors[] = {
    &policy_detector,
    NULL // Null-terminator simplifies loop counting
};

int handle_event(void *ctx, void *data, size_t data_sz) {
    if (!data) return 0;
    
    const struct dlp_event *raw = data;
    enriched_event_t e;

    // 1. Path Resolution - Always runs exactly once per event
    enrich_event(raw, &e);

    // 2. Linear Pipeline Processing Loop
    char reason[256];
    for (int i = 0; detectors[i] != NULL; i++) {
        detection_result_t result = detectors[i]->handle(&e, reason, sizeof(reason));
        
        if (result == DETECTION_ALERT) {
            // Drop findings into the unified JSON reporter layer
            alert_report(detectors[i]->name, &e, reason);
        }
    }

    return 0;
}