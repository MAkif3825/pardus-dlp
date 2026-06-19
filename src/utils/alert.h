#pragma once
#include "../event.h"

// Prints structured security telemetry JSON to standard output
void alert_report(const char *detector_name, const enriched_event_t *e, const char *reason);