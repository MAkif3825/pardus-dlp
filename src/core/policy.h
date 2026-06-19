#pragma once
#include <stdbool.h>

// Loads paths from the policy file into internal static memory
int policy_load(const char *path);

// Computes whether a resolved path matches any sensitive rules
bool policy_is_sensitive(const char *resolved_path);

// Cleans up internal memory arrays upon agent exit
void policy_free(void);