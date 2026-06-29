#ifndef _UTILS_ALERT_H_
#define _UTILS_ALERT_H_

#include "kernel/pardus_dlp.h"

/*
 * Prints structured security telemetry JSON to standard output.
 *
 * Serves as the central logging interceptor. Resolves POSIX user tracking
 * configurations, decodes operational numerical event type masks into legible
 * strings, and maps the total threat profile into a standard formatted JSON
 * output block.
 */
void alert_report(const char* detector_name, const struct dlp_event* e, const char* reason);

#endif /* !_UTILS_ALERT_H_ */