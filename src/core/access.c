#include <bpf/bpf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "../utils/file_utils.h"
#include "access.h"

/* =========================================================================
 * TINY EXTRACTION HELPERS
 * ========================================================================= */
static bool get_next_u8(char** saveptr, uint8_t* out_val)
{
	char* token = strtok_r(NULL, ",", saveptr);
	if (!token)
		return false;
	trim_whitespace(token);
	*out_val = (uint8_t)atoi(token);
	return true;
}

static bool get_next_u32(char** saveptr, uint32_t* out_val)
{
	char* token = strtok_r(NULL, ",", saveptr);
	if (!token)
		return false;
	trim_whitespace(token);
	*out_val = (uint32_t)strtoul(token, NULL, 10);
	return true;
}

static bool get_next_string(char** saveptr, char* out_str, size_t max_len)
{
	char* token = strtok_r(NULL, ",", saveptr);
	if (!token)
		return false;
	trim_whitespace(token);
	strncpy(out_str, token, max_len - 1);
	out_str[max_len - 1] = '\0';
	return true;
}

/* =========================================================================
 * MINI PARSERS FOR EACH RULE METHOD
 * ========================================================================= */
static bool parse_perm_rule(char** saveptr, struct access_policy_value* p_val)
{
	p_val->rule_type = RULE_TYPE_PERM;
	return get_next_u8(saveptr, &p_val->payload.perm.perm_mask);
}

static bool parse_time_rule(char** saveptr, struct access_policy_value* p_val)
{
	p_val->rule_type = RULE_TYPE_TIME;
	if (!get_next_u8(saveptr, &p_val->payload.time.start_hour))
		return false;
	if (!get_next_u8(saveptr, &p_val->payload.time.end_hour))
		return false;
	if (!get_next_u8(saveptr, &p_val->payload.time.work_mask))
		return false;
	if (!get_next_u8(saveptr, &p_val->payload.time.off_mask))
		return false;
	return true;
}

static bool parse_app_rule(char** saveptr, struct access_policy_value* p_val)
{
	p_val->rule_type = RULE_TYPE_APP;
	if (!get_next_string(saveptr, p_val->payload.app.trusted_comm, DLP_COMM_LEN))
		return false;
	return get_next_u8(saveptr, &p_val->payload.app.perm_mask);
}

static bool parse_session_rule(char** saveptr, struct access_policy_value* p_val)
{
	p_val->rule_type = RULE_TYPE_SESSION;
	char context[16] = { 0 };
	if (!get_next_string(saveptr, context, sizeof(context)))
		return false;
	p_val->payload.session.is_remote = (strncmp(context, "REMOTE", 6) == 0) ? 1 : 0;
	return get_next_u8(saveptr, &p_val->payload.session.perm_mask);
}

static bool parse_rate_rule(char** saveptr, struct access_policy_value* p_val)
{
	p_val->rule_type = RULE_TYPE_RATE;
	return get_next_u32(saveptr, &p_val->payload.rate.max_rpm);
}

static bool parse_ext_rule(char** saveptr, struct access_policy_value* p_val)
{
	p_val->rule_type = RULE_TYPE_EXT;
	if (!get_next_string(saveptr, p_val->payload.ext.allowed_ext, 8))
		return false;
	return get_next_u8(saveptr, &p_val->payload.ext.perm_mask);
}

static bool parse_audit_rule(char** saveptr, struct access_policy_value* p_val)
{
	p_val->rule_type = RULE_TYPE_AUDIT;
	return get_next_u8(saveptr, &p_val->payload.audit.audit_mask);
}

/* =========================================================================
 * MAIN COMPILATION ENGINE
 * ========================================================================= */
int access_db_init(const char* db_path, int stage1_map_fd, int stage2_map_fd)
{
	FILE* file;
	struct stat st;
	struct access_policy_key p_key;
	struct access_policy_value p_val;
	char line[512], *token, *saveptr;
	int loaded_count = 0;
	uint32_t dummy_val = 1;

	file = fopen(db_path, "r");
	if (!file)
		return -1;

	while (fgets(line, sizeof(line), file)) {
		trim_whitespace(line);
		if (line[0] == '#' || line[0] == '\0')
			continue;

		memset(&p_key, 0, sizeof(p_key));
		memset(&p_val, 0, sizeof(p_val));

		/* 1. Extract Method */
		token = strtok_r(line, ",", &saveptr);
		if (!token)
			continue;
		char method[16] = { 0 };
		strncpy(method, token, sizeof(method) - 1);
		trim_whitespace(method);

		/* 2. Extract Common Key: Subject Type */
		token = strtok_r(NULL, ",", &saveptr);
		if (!token)
			continue;
		trim_whitespace(token);
		/* 2. Extract Common Key: Subject Type */
		if (strncmp(token, "UID", 3) == 0)
			p_key.subject_type = SUBJECT_TYPE_UID;
		else if (strncmp(token, "GID", 3) == 0)
			p_key.subject_type = SUBJECT_TYPE_GID;
		else if (strncmp(token, "ALL", 3) == 0)
			p_key.subject_type = SUBJECT_TYPE_ALL;
		else
			continue;

		/* 3. Extract Common Key: Subject ID */
		token = strtok_r(NULL, ",", &saveptr);
		if (!token)
			continue;
		p_key.subject_id = (uint32_t)atoi(token);

		/* 4. Extract Common Key: Target Path Inode */
		token = strtok_r(NULL, ",", &saveptr);
		if (!token)
			continue;
		trim_whitespace(token);
		if (stat(token, &st) != 0)
			continue;
		p_key.dir_inode = st.st_ino;

		/* 5. DELEGATE TO MINI PARSERS */
		bool parse_success = false;
		if (strncmp(method, "PERM", 4) == 0)
			parse_success = parse_perm_rule(&saveptr, &p_val);
		else if (strncmp(method, "TIME", 4) == 0)
			parse_success = parse_time_rule(&saveptr, &p_val);
		else if (strncmp(method, "APP", 3) == 0)
			parse_success = parse_app_rule(&saveptr, &p_val);
		else if (strncmp(method, "SESSION", 7) == 0)
			parse_success = parse_session_rule(&saveptr, &p_val);
		else if (strncmp(method, "RATE", 4) == 0)
			parse_success = parse_rate_rule(&saveptr, &p_val);
		else if (strncmp(method, "EXT", 3) == 0)
			parse_success = parse_ext_rule(&saveptr, &p_val);
		else if (strncmp(method, "AUDIT", 5) == 0)
			parse_success = parse_audit_rule(&saveptr, &p_val);

		if (!parse_success) {
			fprintf(stderr, "[!] Warning: Malformed %s rule skipped.\n", method);
			continue;
		}

		/* 6. Push Verified Rule to eBPF Maps */
		bpf_map_update_elem(stage1_map_fd, &p_key.dir_inode, &dummy_val, BPF_ANY);
		if (bpf_map_update_elem(stage2_map_fd, &p_key, &p_val, BPF_ANY) == 0)
			loaded_count++;
	}

	fclose(file);
	return loaded_count;
}