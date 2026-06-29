#pragma once
#include "kernel/pardus_dlp.h"  

/**
 * @brief Prints structured security telemetry JSON to standard output.
 *
 * Serves as the central logging interceptor. Resolves POSIX user tracking configurations,
 * decodes operational numerical event type masks into legible strings, and maps the total 
 * threat profile into a standard formatted JSON output block.
 *
 * @param detector_name String identifier of the detector plugin flagging the event.
 * @param e Pointer to the tracking node container triggering the alert.
 * @param reason Descriptive text buffer containing the rule or signature mismatch detail.
 */
void alert_report(const char *detector_name, const struct dlp_event *e, const char *reason);