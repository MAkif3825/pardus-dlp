#include <bpf/bpf.h>
#include <stdio.h>
#include <string.h>

#include "../core/access.h"
#include "access_detector.h"

static int access_init(void* config);
static enum detection_result access_handle(const struct dlp_event* e, char* reason, size_t rlen);
static void access_destroy(void);

/* Global instantiation of the access detector contract mapping */
struct detector access_detector = {
	.name = "access_engine",
	.init = access_init,
	.handle = access_handle,
	.destroy = access_destroy,
};

static int access_init(void* config)
{
	struct access_config* ctx;
	int records_loaded;
	int fd1, fd2;

	if (config == NULL)
		return (-1);

	/* Cast the generic configuration block to our custom layout. */
	ctx = (struct access_config*)config;
	if (ctx->db_path == NULL || ctx->stage1_map == NULL || ctx->stage2_map == NULL)
		return (-1);

	/* Extract raw file descriptors from libbpf wrappers for the core parser */
	fd1 = bpf_map__fd(ctx->stage1_map);
	fd2 = bpf_map__fd(ctx->stage2_map);

	if (fd1 < 0 || fd2 < 0)
		return (-1);

	/* Fire our core compiler to parse the CSV and load the kernel maps. */
	records_loaded = access_db_init(ctx->db_path, fd1, fd2);
	if (records_loaded < 0)
		return (-1);

	printf("[+] Access policy engine successfully armed with %d matrix rules.\n", records_loaded);
	return (0);
}

static enum detection_result access_handle(const struct dlp_event* e, char* reason, size_t rlen)
{
	if (e == NULL)
		return (DETECTION_PASS);

	/* * 0xBADF is the custom sentinel flag the kernel outputs
	 * when the access matrix blocks an operation.
	 */
	if (e->flags == 0xBADF) {
		snprintf(reason, rlen,
		    "LSM Access Denied [Target Path: %s, User UID: %u, Process: %s]. "
		    "Operation blocked by dynamic access policy matrix.",
		    e->full_path, e->uid, e->comm);

		return (DETECTION_ALERT);
	}

	return (DETECTION_PASS);
}

static void access_destroy(void)
{
	/* Kernel resources tear down automatically with the BPF skeleton */
}