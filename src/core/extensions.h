#pragma once

#include <bpf/libbpf.h>

/**
 * @brief Reads an extension blocklist file and loads strings directly into the
 * eBPF map.
 * @param db_path Path to the plain text file (e.g., "extensions.txt")
 * @param ext_map Pointer to the loaded BPF map object from your skeleton
 * @return int Number of extensions successfully loaded on success, negative
 * error code on failure.
 */
int extension_db_init(const char *db_path, struct bpf_map *ext_map);