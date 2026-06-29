#pragma once
#include "../event.h"

/**
 * @brief Translates raw kernel paths into absolute normalized paths.
 *
 * Intercepts incoming event payloads from the telemetry rings to construct
 * human-readable paths. Relies on active runtime PID paths inside /proc
 * namespaces to resolve relative file references back into static canonical
 * system strings.
 *
 * @param raw Pointer to the incoming telemetry packet from the kernel map.
 * @param out Pointer to the enriched tracking container data structure to
 * populate.
 * @return 0 on success, or -1 if canonicalization fails and falls back to raw
 * data.
 */
int enrich_event(const struct dlp_event *raw, enriched_event_t *out);