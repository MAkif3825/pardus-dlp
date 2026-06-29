#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../utils/file_utils.h"
#include "policy.h"

static char** sensitive_paths = NULL;
static int match_count = 0;

int policy_load(const char* path)
{
	char line[4096];
	char** tmp;
	FILE* f;

	f = fopen(path, "r");
	if (f == NULL)
		return (-1);

	while (fgets(line, sizeof(line), f)) {
		/* This strips spaces, tabs, \r, and \n all in one safe pass.
		 */
		trim_whitespace(line);

		/* Ignore empty rows or comment lines. */
		if (strlen(line) == 0 || line[0] == '#')
			continue;

		tmp = realloc(sensitive_paths, (match_count + 1) * sizeof(char*));
		if (tmp == NULL) {
			fclose(f);
			return (-1); /* Out of memory */
		}
		sensitive_paths = tmp;

		sensitive_paths[match_count] = strdup(line);
		if (sensitive_paths[match_count] == NULL) {
			fclose(f);
			return (-1);
		}
		match_count++;
	}

	fclose(f);
	return (0);
}

bool policy_is_sensitive(const char* resolved_path)
{
	int i;

	if (resolved_path == NULL || match_count == 0)
		return (false);

	/* Evaluate incoming target against our rules array. */
	for (i = 0; i < match_count; i++)
		if (strstr(resolved_path, sensitive_paths[i]) != NULL)
			return (true); /* Match hit! */

	return (false);
}

void policy_free(void)
{
	int i;

	if (sensitive_paths == NULL)
		return;

	for (i = 0; i < match_count; i++)
		free(sensitive_paths[i]);
	free(sensitive_paths);

	sensitive_paths = NULL;
	match_count = 0;
}