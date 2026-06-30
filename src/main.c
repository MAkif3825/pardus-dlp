#include <bpf/libbpf.h>
#include <sys/types.h>

#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "detectors/access_detector.h"
#include "detectors/detector.h"
#include "detectors/extension_detector.h"
#include "dispatch.h"
#include "kernel/pardus_dlp.h"
#include "pardus_dlp.skel.h"

static error_t parse_opt(int key, char* arg, struct argp_state* state);
static void sig_handler(int sig);

static volatile bool exiting = false;

/* Simple structure to hold CLI arguments */
static struct env {
	char* access_path; /* Updated field name */
	char* malware_path;
	char* extensions_path;
	bool verbose;
} env = { .access_path = "access.csv", /* Updated default filename */
	.malware_path = "malware_db.txt",
	.extensions_path = "extensions.txt",
	.verbose = false };

/* Argp configuration details for the Pardus DLP agent */
const char* argp_program_version = "Pardus-DLP v1.0.0";

static char doc[] = "Pardus-DLP: An enterprise-grade eBPF Endpoint Security Sensor.";

static struct argp_option options[] = {
	{ "access", 'a', "FILE", 0, "Path to the dynamic access rules CSV policy file", 0 }, /* Swapped to -a / --access */
	{ "malware", 'm', "FILE", 0, "Path to the MalwareBazaar signature text file", 0 },
	{ "extensions", 'e', "FILE", 0, "Path to the blocked extensions configuration file", 0 },
	{ "verbose", 'v', 0, 0, "Enable verbose debug logs", 0 },
	{ 0 }
};

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
	struct env* e;

	e = state->input;

	switch (key) {
	case 'a': /* Swapped option key */
		e->access_path = arg;
		break;
	case 'm':
		e->malware_path = arg;
		break;
	case 'e':
		e->extensions_path = arg;
		break;
	case 'v':
		e->verbose = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return (ARGP_ERR_UNKNOWN);
	}

	return (0);
}

static struct argp argp = { options, parse_opt, NULL, doc };

static void sig_handler(int sig) { exiting = true; }

/* Forward declare all active plugin contracts */
extern struct detector access_detector;
extern struct detector malware_detector;
extern struct detector extension_detector;

int main(int argc, char** argv)
{
	struct extension_config ext_cfg;
	struct access_config acc_cfg;
	struct pardus_dlp_bpf* skel;
	struct ring_buffer* rb;
	int err;
	bool extension_init;
	bool malware_init;
	bool access_init;

	skel = NULL;
	rb = NULL;

	access_init = false;
	malware_init = false;
	extension_init = false;
	err = 0;

	/* 1. Parse command line configurations */
	if (argp_parse(&argp, argc, argv, 0, 0, &env) != 0)
		return (1);

	/* 2. Register operational termination signals */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* 3. Initialize Standard Independent Plugins */
	printf("[*] Loading signature registry database: %s\n", env.malware_path);
	if (malware_detector.init(env.malware_path) != 0) {
		fprintf(stderr,
		    "[-] Critical Error: Failed to load malware "
		    "signature registry database\n");
		err = 1;
		goto cleanup;
	}
	malware_init = true;

	/* 4. Open and Bootstrap the eBPF Kernel Skeleton */
	skel = pardus_dlp_bpf__open();
	if (skel == NULL) {
		fprintf(stderr, "[-] Failed to open eBPF skeleton\n");
		err = 1;
		goto cleanup;
	}

	/* Enforce global user-space filters into kernel map configurations. */
	skel->rodata->my_pid = getpid();

	err = pardus_dlp_bpf__load(skel);
	if (err != 0) {
		fprintf(stderr, "[-] Failed to load and verify eBPF skeleton\n");
		goto cleanup;
	}

	/* 5. Initialize Kernel-dependent Plugins (Now that maps exist!) */
	printf("[*] Arming dynamic access matrices: %s\n", env.access_path);
	acc_cfg.db_path = env.access_path;

	/* Map these directly to the variables declared in your BPF code */
	acc_cfg.stage1_map = skel->maps.stage1_inode_map;
	acc_cfg.stage2_map = skel->maps.stage2_policy_map;

	if (access_detector.init(&acc_cfg) != 0) {
		fprintf(stderr,
		    "[-] Critical Error: Failed to arm dynamic access "
		    "policy maps\n");
		err = 1;
		goto cleanup;
	}
	access_init = true;

	/* Extension engine initialization remains right below this */
	printf("[*] Arming blocklist extension parameters: %s\n", env.extensions_path);
	ext_cfg.db_path = env.extensions_path;
	ext_cfg.ext_map = skel->maps.extensions;

	if (extension_detector.init(&ext_cfg) != 0) {
		fprintf(stderr,
		    "[-] Critical Error: Failed to arm kernel "
		    "extension map blocklists\n");
		err = 1;
		goto cleanup;
	}
	extension_init = true;

	/* 6. Attach Hooks to Kernel LSM Layer */
	err = pardus_dlp_bpf__attach(skel);
	if (err != 0) {
		fprintf(stderr, "[-] Failed to attach eBPF kernel hooks\n");
		goto cleanup;
	}

	/* 7. Setup the Performance/Ring Buffer Boundary */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (rb == NULL) {
		fprintf(stderr, "[-] Failed to create user-space ring buffer bridge\n");
		err = 1;
		goto cleanup;
	}

	printf("[+] Pardus-DLP Agent active and monitoring system calls.\n");

	/* 8. Main Infinite Telemetry Stream Loop */
	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			continue;
		if (err < 0) {
			fprintf(stderr, "[-] Error polling eBPF ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	printf("\n[*] Cleaning up and tearing down security layers safely...\n");

	if (rb != NULL)
		ring_buffer__free(rb);
	if (skel != NULL)
		pardus_dlp_bpf__destroy(skel);
	if (extension_init && extension_detector.destroy != NULL)
		extension_detector.destroy();
	if (malware_init && malware_detector.destroy != NULL)
		malware_detector.destroy();
	if (access_init && access_detector.destroy != NULL)
		access_detector.destroy();

	printf("[+] Shutdown complete.\n");
	return (err < 0 ? 1 : err);
}