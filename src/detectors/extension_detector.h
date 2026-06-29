#pragma once
#include <bpf/libbpf.h>

typedef struct {
    const char *db_path;
    struct bpf_map *ext_map;
} extension_config_t;