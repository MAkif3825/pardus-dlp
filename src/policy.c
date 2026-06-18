#include "policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char **sensitive_paths = NULL;
static int match_count = 0;

int policy_load(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        return -1;
    }

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        // Strip trailing newline character safely
        line[strcspn(line, "\n")] = 0;
        
        // Ignore empty rows or comment lines
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }

        char **tmp = realloc(sensitive_paths, (match_count + 1) * sizeof(char *));
        if (!tmp) {
            fclose(f);
            return -1; // Out of memory
        }
        sensitive_paths = tmp;
        
        sensitive_paths[match_count] = strdup(line);
        if (!sensitive_paths[match_count]) {
            fclose(f);
            return -1;
        }
        match_count++;
    }

    fclose(f);
    return 0;
}

bool policy_is_sensitive(const char *resolved_path) {
    if (!resolved_path || match_count == 0) {
        return false;
    }

    // Evaluate incoming target against our rules array
    for (int i = 0; i < match_count; i++) {
        if (strstr(resolved_path, sensitive_paths[i]) != NULL) {
            return true; // Match hit!
        }
    }
    return false;
}

void policy_free(void) {
    if (!sensitive_paths) {
        return;
    }

    for (int i = 0; i < match_count; i++) {
        free(sensitive_paths[i]);
    }
    free(sensitive_paths);
    
    sensitive_paths = NULL;
    match_count = 0;
}