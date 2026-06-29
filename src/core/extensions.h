#ifndef _CORE_EXTENSIONS_H_
#define _CORE_EXTENSIONS_H_

#include <bpf/libbpf.h>

/*
 * Reads an extension blocklist file and loads strings directly into the
 * eBPF map.
 *
 * Returns the number of extensions successfully loaded on success, or a
 * negative error code on failure.
 */
int extension_db_init(const char* db_path, struct bpf_map* ext_map);

#endif /* !_CORE_EXTENSIONS_H_ */