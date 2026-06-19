#pragma once
#include <stddef.h>

// Universal event handler targeted by the eBPF ring buffer
int handle_event(void *ctx, void *data, size_t data_sz);