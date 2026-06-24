#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <argp.h>
#include <bpf/libbpf.h>

#include "kernel/pardus_dlp.h"
#include "pardus_dlp.skel.h" 
#include "dispatch.h"        
#include "detectors/detector.h"

static volatile bool exiting = false;

// Simple structure to hold CLI arguments
static struct env {
    char *policy_path;
    char *malware_path; 
    bool verbose;
} env = {
    .policy_path = "policy.txt",
    .malware_path = "malware_db.txt", 
    .verbose = false
};

// Argp configuration details for the Pardus DLP agent
const char *argp_program_version = "Pardus-DLP v1.0.0";
static char doc[] = "Pardus-DLP: An enterprise-grade eBPF Endpoint Security Sensor.";
static struct argp_option options[] = {
    {"policy",  'p', "FILE", 0, "Path to the sensitive directories policy file", 0},
    {"malware", 'm', "FILE", 0, "Path to the MalwareBazaar signature text file", 0}, 
    {"verbose", 'v', 0,      0, "Enable verbose debug logs", 0},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    struct env *e = state->input;
    switch (key) {
        case 'p':
            e->policy_path = arg;
            break;
        case 'm':
            e->malware_path = arg;
            break;
        case 'v':
            e->verbose = true;
            break;
        case ARGP_KEY_ARG:
             argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static struct argp argp = { options, parse_opt, 0, doc };

static void sig_handler(int sig) {
    exiting = true;
}

// Forward declare the plugin instances to initialize them
extern detector_t policy_detector;
extern detector_t malware_detector; 

int main(int argc, char **argv) {
    struct pardus_dlp_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    
    // Explicit tracking variables initialized for the cleanup block below
    bool policy_init = false;
    bool malware_init = false;
    int err = 0;

    // 1. Parse command line configurations
    if (argp_parse(&argp, argc, argv, 0, 0, &env) != 0) {
        return 1;
    }

    // 2. Register operational termination signals
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 3. Initialize Active Plugins (Using the Config Arguments)
    printf("[*] Loading policy database: %s\n", env.policy_path);
    if (policy_detector.init(env.policy_path) != 0) {
        fprintf(stderr, "[-] Critical Error: Failed to initialize policy detector plugin\n");
        err = 1;
        goto cleanup;
    }
    policy_init = true;

    printf("[*] Loading signature registry database: %s\n", env.malware_path); 
    if (malware_detector.init(env.malware_path) != 0) {
        fprintf(stderr, "[-] Critical Error: Failed to load malware signature registry database\n");
        err = 1;
        goto cleanup;
    }
    malware_init = true;

    // 4. Open and Bootstrap the eBPF Kernel Skeleton
    skel = pardus_dlp_bpf__open();
    if (!skel) {
        fprintf(stderr, "[-] Failed to open eBPF skeleton\n");
        err = 1;
        goto cleanup;
    }

    // Enforce global user-space filter values directly into the kernel map configurations
    skel->rodata->my_pid = getpid();

    err = pardus_dlp_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to load and verify eBPF skeleton\n");
        goto cleanup;
    }

    err = pardus_dlp_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "[-] Failed to attach eBPF kernel hooks\n");
        goto cleanup;
    }

    // 5. Setup the Performance/Ring Buffer Boundary
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "[-] Failed to create user-space ring buffer bridge\n");
        err = 1;
        goto cleanup;
    }

    printf("[+] Pardus-DLP Agent active and monitoring system calls successfully.\n");

    // 6. Main Infinite Telemetry Stream Loop
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout execution window, ms */);
        if (err == -EINTR) {
            continue;
        }
        if (err < 0) {
            fprintf(stderr, "[-] Error polling eBPF ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    printf("\n[*] Cleaning up and tearing down security layers safely...\n");
    
    if (rb) {
        ring_buffer__free(rb);
    }
    if (skel) {
        pardus_dlp_bpf__destroy(skel);
    }
    if (malware_init && malware_detector.destroy) {
        malware_detector.destroy();
    }
    if (policy_init && policy_detector.destroy) {
        policy_detector.destroy();
    }

    printf("[+] Shutdown complete.\n");
    return err < 0 ? 1 : err;
}