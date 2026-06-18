#pragma once
#include "event.h"

// Translates raw kernel paths into absolute normalized paths.
// Fills out->resolved_path. Returns 0 on success, -1 on fallback.
int enrich_event(const struct dlp_event *raw, enriched_event_t *out);