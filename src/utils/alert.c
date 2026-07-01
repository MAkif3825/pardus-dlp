#include <fcntl.h> /* Required for O_ACCMODE, O_WRONLY, O_RDONLY, etc. */
#include <pwd.h>
#include <stdio.h>
#include <time.h>

#include "alert.h"

void alert_report(const char* detector_name, const struct dlp_event* e, const char* reason)
{
	char ts[32];
	struct passwd* pw;
	struct tm* tm;
	const char* op_name;
	const char* username;
	time_t t;
	unsigned int access_mode;

	/* 1. Generate Timestamp */
	t = time(NULL);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm);

	/* 2. Resolve Username */
	pw = getpwuid(e->uid);
	username = (pw != NULL) ? pw->pw_name : "unknown";

	/* 3. Decode the raw kernel flags natively in user-space */
	op_name = "UNKNOWN";

	if (e->flags == 0xDEAD) {
		op_name = "EXECUTE (EXTENSION_BLOCK)";
	} else if (e->flags == 0xECEE) {
		op_name = "EXECUTE (POLICY_BLOCK)";
	} else if (e->flags == 0xBADF) {
		op_name = "FILE_OPEN (POLICY_BLOCK)";
	} else {
		/* Not a block flag. Decode normal file modes for audit logs. */
		access_mode = e->flags & O_ACCMODE;
		if (access_mode == O_WRONLY)
			op_name = "WRITE";
		else if (access_mode == O_RDONLY)
			op_name = "READ";
		else if (access_mode == O_RDWR)
			op_name = "READ/WRITE";
	}

	/* 4. Generate Structured JSON Output */
	printf("{\n");
	printf("  \"timestamp\": \"%s\",\n", ts);
	printf("  \"detector\": \"%s\",\n", detector_name);
	printf("  \"verdict\": \"ALERT\",\n");
	printf("  \"reason\": \"%s\",\n", reason);
	printf("  \"process_name\": \"%s\",\n", e->comm);
	printf("  \"pid\": %u,\n", e->pid);
	printf("  \"uid\": %u,\n", e->uid);
	printf("  \"username\": \"%s\",\n", username);
	printf("  \"file_path\": \"%s\",\n", e->full_path);
	printf("  \"operation\": \"%s\",\n", op_name);
	printf("  \"raw_flags\": \"0x%x\"\n", e->flags);
	printf("}\n");
}