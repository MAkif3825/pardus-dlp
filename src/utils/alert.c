#include "alert.h"
#include <stdio.h>
#include <time.h>
#include <pwd.h>

void alert_report(const char *detector_name, const struct dlp_event *e, const char *reason) {
    struct tm *tm;
    char ts[32];
    time_t t = time(NULL);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm); 

    struct passwd *pw = getpwuid(e->uid);
    const char *username = pw ? pw->pw_name : "unknown";

    // Decode the raw kernel flags natively in user-space
    const char *op_name = "UNKNOWN";
    
    if (e->flags == 0xDEAD) {
        op_name = "EXECUTE_BLOCK";
    } else {
        unsigned int access_mode = e->flags & O_ACCMODE;
        if (access_mode == O_WRONLY) {
            op_name = "WRITE";
        } else if (access_mode == O_RDONLY) {
            op_name = "READ";
        } else if (access_mode == O_RDWR) {
            op_name = "READ/WRITE";
        }
    }

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