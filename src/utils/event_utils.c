#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event_utils.h"

int enrich_event(const struct dlp_event* raw, struct enriched_event* out)
{
	char proc_path[4096];
	const char* input_path;

	out->raw = raw;

	memset(proc_path, 0, sizeof(proc_path));
	input_path = raw->filename;

	/* Relative path bridge assembly via /proc. */
	if (raw->filename[0] != '/') {
		snprintf(proc_path, sizeof(proc_path), "/proc/%d/cwd/%s", raw->pid, raw->filename);
		input_path = proc_path;
	}

	/* Attempt absolute canonicalization. */
	if (realpath(input_path, out->resolved_path) == NULL) {
		/*
		 * Fallback: copy raw filename directly so processing can
		 * continue safely.
		 */
		strncpy(out->resolved_path, raw->filename, sizeof(out->resolved_path));
		return (-1);
	}

	return (0);
}