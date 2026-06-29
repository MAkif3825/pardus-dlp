#include "file_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <string.h>

bool file_utils_calculate_sha256(const char *filepath, char *out_sha256, size_t max_size_bytes) {
    if (!filepath || !out_sha256) {
        return false;
    }

    // 🛡️ GUARDRAIL 1: Query file metadata directly from OS inode (Does not read contents)
    struct stat st;
    if (stat(filepath, &st) != 0) {
        return false; // File doesn't exist or permissions denied
    }

    // Ensure we are dealing with a regular file, skipping directories, pipes, and sockets
    if (!S_ISREG(st.st_mode)) {
        return false;
    }

    // Protect against the 10 GB file freeze attack vector
    if ((size_t)st.st_size > max_size_bytes) {
        return false;
    }

    // Attempt to open the file for binary reading
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        return false;
    }

    // OpenSSL EVP API Setup (Modern, optimized crypto library interface)
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        fclose(file);
        return false;
    }

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        fclose(file);
        return false;
    }

    // Stream data chunk-by-chunk using a clean 4KB buffer
    unsigned char buffer[4096];
    size_t bytes_read;
    bool success = true;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(md_ctx, buffer, bytes_read) != 1) {
            success = false;
            break;
        }
    }

    // Finalize the cryptographic digest calculation
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    if (success && EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
        success = false;
    }

    // Clean up resources immediately
    EVP_MD_CTX_free(md_ctx);
    fclose(file);

    if (!success) {
        return false;
    }

    // Convert the raw binary bytes into a clean 64-character hexadecimal string
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(&out_sha256[i * 2], "%02x", hash[i]);
    }
    out_sha256[64] = '\0';

    return true;
}

void trim_whitespace(char *str) {
    char *end;
    if (!str) return;

    // 1. Skip leading whitespace by moving the starting pointer forward
    while (isspace((unsigned char)*str)) {
        str++;
    }
    
    // If the string was entirely whitespace, we are done
    if (*str == 0) return;                      
    
    // 2. Start from the very end of the string and look backward
    end = str + strlen(str) - 1;               
    while (end > str && isspace((unsigned char)*end)) {
        end--; 
    }
    
    // 3. Drop a clean Null Terminator directly into memory right after the last character
    *(end + 1) = '\0';            
}