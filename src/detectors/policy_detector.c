#include <stdio.h>
#include <string.h>

#include "../core/policy.h"
#include "detector.h"

static int policy_init(void* config);
static enum detection_result policy_handle(const struct dlp_event* e, char* reason, size_t rlen);
static void policy_destroy(void);

/* Global instantiation of our plugin object */
struct detector policy_detector = {
	.name = "policy_engine",
	.init = policy_init,
	.handle = policy_handle,
	.destroy = policy_destroy,
};

static int policy_init(void* config)
{
	const char* path;

	path = (const char*)config;

	return (policy_load(path));
}

static enum detection_result policy_handle(const struct dlp_event* e, char* reason, size_t rlen)
{
	if (e == NULL)
		return (DETECTION_PASS);

	if (policy_is_sensitive(e->full_path)) {
		snprintf(reason, rlen, "Path matches sensitive watchlist rule");
		return (DETECTION_ALERT);
	}

	return (DETECTION_PASS);
}

static void policy_destroy(void) { policy_free(); }