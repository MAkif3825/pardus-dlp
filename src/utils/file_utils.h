#ifndef _UTILS_FILE_UTILS_H_
#define _UTILS_FILE_UTILS_H_

#include <stdbool.h>
#include <stddef.h>

/*
 * Checks a file's size and computes its SHA256 cryptographic hash string.
 *
 * This function performs pre-computation validation by reading file traits.
 * If the target file satisfies the user-defined maximum size limits, it parses
 * binary file streams through an OpenSSL context loop to map unique
 * signatures.
 *
 * Returns true if successfully hashed; false if skipped or failed.
 */
bool file_utils_calculate_sha256(const char* filepath, char* out_sha256, size_t max_size_bytes);

/* Strips leading and trailing whitespace/newlines from a string in-place. */
void trim_whitespace(char* str);

#endif /* !_UTILS_FILE_UTILS_H_ */