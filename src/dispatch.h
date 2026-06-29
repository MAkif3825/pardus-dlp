#ifndef _DISPATCH_H_
#define _DISPATCH_H_

#include <stddef.h>

/* Universal event handler targeted by the eBPF ring buffer. */
int handle_event(void* ctx, void* data, size_t data_sz);

#endif /* !_DISPATCH_H_ */