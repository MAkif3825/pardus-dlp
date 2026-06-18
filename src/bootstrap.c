// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <pwd.h>
#include <unistd.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

#define MAX_MATCH_COUNT 128

//Sensitive paths are loaded from txt file
static char *sensitive_paths[MAX_MATCH_COUNT];

// This replaces your old macro definition with a live counter variable
static int match_count = 0;
static struct env {
	bool verbose;
	const char *policy_path;
} env = {
	.policy_path = NULL
};

const char *argp_program_version = "pardus-dlp 1.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"Pardus Mini-DLP Security Monitoring Agent.\n"
"\n"
"USAGE: ./bootstrap -p <policy_file> [-v]\n";

static const struct argp_option opts[] = {
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    { "policy", 'p', "POLICY-FILE", 0, "Path to the sensitive files list configuration (REQUIRED)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v':
        env.verbose = true;
        break;
    case 'p':
        env.policy_path = arg;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)	
{
	exiting = true;
}

static int load_policies(const char *config_path)
{
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        fprintf(stderr, "[-] Failed to open policy file: %s\n", config_path);
        return -1;
    }

    char line[4096];
    while (fgets(line, sizeof(line), fp) && match_count < MAX_MATCH_COUNT) {
        // Strip trailing newline character (\n or \r) if present
        line[strcspn(line, "\r\n")] = '\0';

        // Skip blank lines
        if (strlen(line) == 0) {
            continue;
        }

        // Allocate memory and copy the path string into our global array
        sensitive_paths[match_count] = strdup(line);
        if (sensitive_paths[match_count]) {
            match_count++;
        }
    }

    fclose(fp);
    printf("[+] Successfully loaded %d policy rules from %s\n", match_count, config_path);
    return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct dlp_event *e = data;
    char resolved_path[4096];
    struct passwd *pw; 
    const char *username; 

    // Fetch the current system time for the log
    struct tm *tm;
    char ts[32];
    time_t t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm); 

    // Path resolution. Needed to eliminate the relative paths
    char proc_path[4096];
    const char *input_path = e->filename;

    if (e->filename[0] != '/') {
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/cwd/%s", e->pid, e->filename);
        input_path = proc_path; 
    }

    // Single unified validation and symlink-breaking point
    if (realpath(input_path, resolved_path) == NULL) {
        strncpy(resolved_path, e->filename, sizeof(resolved_path));
    }

    // Check if the path is in the filter list
    bool is_sensitive = false;
    for (int i = 0; i < match_count; i++) {
        if (strstr(resolved_path, sensitive_paths[i]) != NULL) {
            is_sensitive = true;
            break;
        }
    }

    if (!is_sensitive) {
        return 0; 
    }

    // Get the username from uid
    pw = getpwuid(e->uid);
    username = pw ? pw->pw_name : "unknown";

    const char *op_name = "UNKNOWN";
    if (e->op_type == DLP_OP_OPEN)      op_name = "OPEN/READ";
    else if (e->op_type == DLP_OP_WRITE) op_name = "WRITE";
    else if (e->op_type == DLP_OP_CLOSE) op_name = "CLOSE";

    // 4. Print Telemetry
    printf("{\n");
    printf("  \"timestamp\": \"%s\",\n", ts);  
    printf("  \"process_name\": \"%s\",\n", e->comm);
    printf("  \"pid\": %d,\n", e->pid);
    printf("  \"uid\": %d,\n", e->uid);
    printf("  \"username\": \"%s\",\n", username); 
    printf("  \"file_path\": \"%s\",\n", resolved_path);
    printf("  \"operation\": \"%s\",\n", op_name); 
    printf("  \"raw_flags\": \"0x%x\"\n", e->flags);
    printf("}\n");

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct bootstrap_bpf *skel;
    int err;

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    // 1. Check if the user forgot the flag entirely
    if (env.policy_path == NULL) {
        fprintf(stderr, "[WARNING] Missing parameter. Please use: -p <policy_file>\n");
        return 1;
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // 2. Load policies using the dynamic command-line argument variable
    if (load_policies(env.policy_path) < 0) {
        return 1;
    }

    // 3. Double-check that the target file actually contained rules
    if (match_count == 0) {
        fprintf(stderr, "[WARNING] Policy file '%s' is empty. Nothing to monitor!\n", env.policy_path);
        return 1;
    }

    /* Load and verify BPF application */
    skel = bootstrap_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    // Tell the kernel probe to ignore our own user-space process ID
	skel->rodata->my_pid = getpid(); 

    /* Load & verify BPF programs */
    err = bootstrap_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = bootstrap_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    bootstrap_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
