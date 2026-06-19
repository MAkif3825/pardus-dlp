#pragma once
#include "kernel/pardus_dlp.h"   

typedef struct {
    char resolved_path[4096];       
    const struct dlp_event *raw;   
} enriched_event_t;