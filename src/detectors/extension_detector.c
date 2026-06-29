#include <stdio.h>
#include <string.h>

#include "../core/extensions.h"
#include "detector.h"
#include "extension_detector.h"

static int extension_init(void* config);
static enum detection_result extension_handle(const struct dlp_event* e, char* reason, size_t rlen);
static void extension_destroy(void);

/* Global instantiation of the extension detector contract mapping */
struct detector extension_detector = {
	.name = "extension_engine",
	.init = extension_init,
	.handle = extension_handle,
	.destroy = extension_destroy,
};

static int extension_init(void* config)
{
	struct extension_config* ctx;
	int records_loaded;

	if (config == NULL)
		return (-1);

	/* Cast the generic configuration block to our custom layout. */
	ctx = (struct extension_config*)config;
	if (ctx->ext_map == NULL || ctx->db_path == NULL)
		return (-1);

	/* Fire our core loader to push the data straight into the kernel. */
	records_loaded = extension_db_init(ctx->db_path, ctx->ext_map);
	if (records_loaded < 0)
		return (-1);

	printf("[+] Extension engine successfully armed with %d rules.\n", records_loaded);
	return (0);
}

static enum detection_result extension_handle(const struct dlp_event* e, char* reason, size_t rlen)
{
	const char* ext;

	if (e == NULL)
		return (DETECTION_PASS);

	/* Check if the event matches our custom sentinel block flag. */
	if (e->flags == 0xDEAD) {
		/* Find the extension in the path string to generate an alert.
		 */
		ext = strrchr(e->full_path, '.');

		if (ext != NULL) {
			ext++; /* Move past the dot (e.g. ".pdf" -> "pdf") */

			snprintf(reason, rlen,
			    "LSM Blocked execution of masquerading binary "
			    "hidden as a data document [Extension: .%s, "
			    "Process: %s, Path: %s]",
			    ext, e->comm, e->full_path);

			return (DETECTION_ALERT);
		}
	}

	return (DETECTION_PASS);
}

static void extension_destroy(void)
{
	/*
	 * eBPF maps are cleaned up automatically when the main application
	 * unloads the skeleton!
	 */
}