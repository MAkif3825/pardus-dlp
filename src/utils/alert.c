#include "alert.h"
#include <stdio.h>
#include <time.h>
#include <pwd.h>

void alert_report(const char *detector_name, const enriched_event_t *e, const char *reason) {
    struct tm *tm;
    char ts[32];
    time_t t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm); 

    struct passwd *pw = getpwuid(e->raw->uid);
    const char *username = pw ? pw->pw_name : "unknown";

    // Dynamic translation of the operation type enum
    const char *op_name = "UNKNOWN";
    if (e->raw->op_type == 1)      op_name = "OPEN/READ";
    else if (e->raw->op_type == 2) op_name = "WRITE";
    else if (e->raw->op_type == 3) op_name = "CLOSE";

    printf("{\n");
    printf("  \"timestamp\": \"%s\",\n", ts);  
    printf("  \"detector\": \"%s\",\n", detector_name);
    printf("  \"verdict\": \"ALERT\",\n");
    printf("  \"reason\": \"%s\",\n", reason);
    printf("  \"process_name\": \"%s\",\n", e->raw->comm);
    printf("  \"pid\": %u,\n", e->raw->pid);
    printf("  \"uid\": %u,\n", e->raw->uid);
    printf("  \"username\": \"%s\",\n", username); 
    printf("  \"file_path\": \"%s\",\n", e->resolved_path);
    printf("  \"operation\": \"%s\",\n", op_name); 
    printf("  \"raw_flags\": \"0x%x\"\n", e->raw->flags); 
    printf("}\n");
}