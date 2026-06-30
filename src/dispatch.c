#include "dispatch.h"
#include "detectors/detector.h"
#include "utils/alert.h"

/* Forward declare the active detector plugins */
extern struct detector access_detector; /* <-- Replaces policy_detector */
extern struct detector malware_detector;
extern struct detector extension_detector;

/*
 * Null-terminated array of active detector plugins.
 * The dispatcher will pipeline events through these sequentially.
 */
static struct detector* detectors[] = {
	&access_detector,
	&malware_detector,
	&extension_detector,
	NULL
};

int handle_event(void* ctx, void* data, size_t data_sz)
{
	const struct dlp_event* raw;
	char reason[256];
	enum detection_result result;
	int i;

	if (data == NULL || data_sz < sizeof(struct dlp_event))
		return (0);

	raw = data;

	/* Pipeline the event through all registered detection engines */
	for (i = 0; detectors[i] != NULL; i++) {
		if (detectors[i]->handle == NULL)
			continue;

		result = detectors[i]->handle(raw, reason, sizeof(reason));

		if (result == DETECTION_ALERT)
			alert_report(detectors[i]->name, raw, reason);
	}

	return (0);
}