#include "../core/policy.h"
#include "detector.h"
#include <stdio.h>
#include <string.h>

static int
policy_init(void *config)
{
	const char *path = (const char *)config;
	return policy_load(path);
}

static detection_result_t
policy_handle(const struct dlp_event *e, char *reason, size_t rlen)
{

	if (!e)
		return DETECTION_PASS;

	if (policy_is_sensitive(e->full_path)) {
		snprintf(reason, rlen,
			 "Path matches sensitive watchlist rule");
		return DETECTION_ALERT;
	}
	return DETECTION_PASS;
}

static void
policy_destroy(void)
{
	policy_free();
}

// Global instantiation of our plugin object
detector_t policy_detector = {
	.name	 = "policy_engine",
	.init	 = policy_init,
	.handle	 = policy_handle,
	.destroy = policy_destroy,
};