#include "file_utils.h"
#include <ctype.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

bool
file_utils_calculate_sha256(const char *filepath, char *out_sha256,
			    size_t max_size_bytes)
{
	struct stat st;
	FILE *file;
	EVP_MD_CTX *md_ctx;
	unsigned char buffer[4096];
	unsigned char hash[EVP_MAX_MD_SIZE];
	size_t bytes_read;
	unsigned int hash_len;
	bool success;

	if (!filepath || !out_sha256)
		return (false);

	if (stat(filepath, &st) != 0)
		return (false);

	if (!S_ISREG(st.st_mode))
		return (false);

	if ((size_t)st.st_size > max_size_bytes)
		return (false);

	file = fopen(filepath, "rb");
	if (!file)
		return (false);

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		fclose(file);
		return (false);
	}

	if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(md_ctx);
		fclose(file);
		return (false);
	}

	success = true;
	while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
		if (EVP_DigestUpdate(md_ctx, buffer, bytes_read) != 1) {
			success = false;
			break;
		}
	}

	hash_len = 0;
	if (success && EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1)
		success = false;

	EVP_MD_CTX_free(md_ctx);
	fclose(file);

	if (!success)
		return (false);

	for (unsigned int i = 0; i < hash_len; i++)
		sprintf(&out_sha256[i * 2], "%02x", hash[i]);
	out_sha256[64] = '\0';

	return (true);
}


void
trim_whitespace(char *str)
{
	char *end;

	if (!str)
		return;

	while (isspace((unsigned char)*str))
		str++;

	if (*str == 0)
		return;

	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end))
		end--;

	*(end + 1) = '\0';
}