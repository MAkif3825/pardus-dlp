#include "detector.h"
#include "../core/extensions.h"
#include "extension_detector.h"
#include <string.h>
#include <stdio.h>

static int extension_init(void *config) {
    if (!config) {
        return -1;
    }

    // Cast the generic configuration block to our custom extension configuration layout
    extension_config_t *ctx = (extension_config_t *)config;
    if (!ctx->ext_map || !ctx->db_path) {
        return -1;
    }
    
    // Fire our core loader to push the extensions.txt data straight into the kernel map register
    int records_loaded = extension_db_init(ctx->db_path, ctx->ext_map);
    if (records_loaded < 0) {
        return -1;  
    }
    
    printf("[+] Extension engine successfully armed with %d rules.\n", records_loaded);
    return 0; 
}

static detection_result_t extension_handle(const struct dlp_event *e,
                                        char *reason, size_t rlen) {
    if (!e) {
        return DETECTION_PASS;
    }

    // Check if the event matches our custom sentinel execution block flag
    if (e->flags == 0xDEAD) {
        // Find the extension in the path string to generate a clean alert message
        const char *ext = strrchr(e->full_path, '.');
        
        if (ext != NULL) {
            ext++; // Move past the dot (e.g. ".pdf" -> "pdf")
            
            snprintf(reason, rlen, 
                     "LSM Blocked execution of masquerading binary hidden as a data document [Extension: .%s, Process: %s, Path: %s]", 
                     ext, e->comm, e->full_path);
            
            return DETECTION_ALERT; // Trigger an explicit alert flag to your main loop!
        }
    }

    return DETECTION_PASS;  
}

static void extension_destroy(void) {
    // eBPF maps are cleaned up automatically when the main application unloads the skeleton!
}

// Global instantiation of the extension detector contract mapping
detector_t extension_detector = {
    .name    = "extension_engine",
    .init    = extension_init,
    .handle  = extension_handle,
    .destroy = extension_destroy,
};