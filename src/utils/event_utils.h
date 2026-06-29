#ifndef _UTILS_EVENT_UTILS_H_
#define _UTILS_EVENT_UTILS_H_

#include "../event.h"

/*
 * Translates raw kernel paths into absolute normalized paths.
 *
 * Intercepts incoming event payloads from the telemetry rings to construct
 * human-readable paths. Relies on active runtime PID paths inside /proc
 * namespaces to resolve relative file references back into static canonical
 * system strings.
 *
 * Returns 0 on success, or -1 if canonicalization fails and falls back to
 * raw data.
 */
int enrich_event(const struct dlp_event* raw, struct enriched_event* out);

#endif /* !_UTILS_EVENT_UTILS_H_ */