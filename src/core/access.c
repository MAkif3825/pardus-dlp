#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../utils/file_utils.h"
#include "access.h"

/* * A clean utility to extract tokens and safely determine if they contain
 * valid numeric configuration data or a wildcard dash.
 * Returns true if a valid numeric module value was loaded.
 */
static bool parse_module_field(char** saveptr, uint8_t* out_val)
{
	char* token;

	token = strtok_r(NULL, ",", saveptr);
	if (token && token[0] != '\0' && token[0] != '-' && token[0] != ' ') {
		/* Strip trailing whitespace if any inside the token field */
		trim_whitespace(token);

		if (strlen(token) > 0 && token[0] != '-') {
			*out_val = (uint8_t)atoi(token);
			return (true);
		}
	}
	return (false);
}

int access_db_init(const char* db_path, int stage1_map_fd, int stage2_map_fd)
{
	FILE* file;
	struct stat st;
	struct access_policy_key p_key;
	struct access_policy_value p_val;
	char line[512];
	char* token;
	char* saveptr;
	int loaded_count = 0;
	uint32_t dummy_val = 1;

	file = fopen(db_path, "r");
	if (!file)
		return (-1);

	while (fgets(line, sizeof(line), file)) {
		trim_whitespace(line);

		if (line[0] == '#' || line[0] == '\0')
			continue;

		memset(&p_key, 0, sizeof(p_key));
		memset(&p_val, 0, sizeof(p_val));

		/* 1. Subject Type Extraction */
		token = strtok_r(line, ",", &saveptr);
		if (!token)
			continue;

		if (strncmp(token, "UID", 3) == 0)
			p_key.subject_type = SUBJECT_TYPE_UID;
		else if (strncmp(token, "GID", 3) == 0)
			p_key.subject_type = SUBJECT_TYPE_GID;
		else
			continue;

		/* 2. Subject ID Extraction */
		token = strtok_r(NULL, ",", &saveptr);
		if (!token)
			continue;
		p_key.subject_id = (uint32_t)atoi(token);

		/* 3. Target Path Resolution */
		token = strtok_r(NULL, ",", &saveptr);
		if (!token || stat(token, &st) != 0)
			continue;
		p_key.dir_inode = st.st_ino;

		/* --- USE THE UTILITY TO MAP THE OPTIONAL SUBSYSTEMS --- */

		/* 4. Time Shift Module Evaluation */
		if (parse_module_field(&saveptr, &p_val.start_hour)) {
			p_val.enabled_modules |= MODULE_TIME;
		}

		/* Notice how saveptr is automatically tracked and updated sequentially */
		parse_module_field(&saveptr, &p_val.end_hour);

		/* 5. Permission Operation Module Evaluation */
		if (parse_module_field(&saveptr, &p_val.allow_write)) {
			p_val.enabled_modules |= MODULE_OP_TYPE;
		}

		/* * FUTURE EXTENSION EXAMPLE:
		 * 6. Application Whitelist Module Evaluation
		 * if (parse_module_field(&saveptr, &p_val.app_id)) {
		 * p_val.enabled_modules |= MODULE_APP_WHITELIST;
		 * }
		 */

		/* --- KERNEL SYNCHRONIZATION --- */
		bpf_map_update_elem(stage1_map_fd, &p_key.dir_inode, &dummy_val, BPF_ANY);

		if (bpf_map_update_elem(stage2_map_fd, &p_key, &p_val, BPF_ANY) == 0) {
			loaded_count++;
		}
	}

	fclose(file);
	return (loaded_count);
}