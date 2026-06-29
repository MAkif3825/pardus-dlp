#pragma once

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Checks a file's size and computes its SHA256 cryptographic hash string.
 *
 * This function performs pre-computation validation by reading file traits. 
 * If the target file satisfies the user-defined maximum size limits, it parses 
 * binary file streams through an OpenSSL context loop to map unique signatures.
 *
 * @param filepath The absolute path to the target file.
 * @param out_sha256 Minimum 65-byte buffer to store the resulting hex string.
 * @param max_size_bytes The maximum size limit (in bytes) allowed for hashing.
 * @return true if successfully hashed; false if skipped (too large) or failed.
 */
bool file_utils_calculate_sha256(const char *filepath, char *out_sha256, size_t max_size_bytes);

/**
 * @brief Strips leading and trailing whitespace/newlines from a string in-place.
 * @param str The string to modify.
 */
void trim_whitespace(char *str);