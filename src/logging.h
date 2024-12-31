#ifndef LOGGING_H
#define LOGGING_H

#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "constants.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

// Global variables declarations - always declare as extern
extern bool use_syslog;
extern bool use_colors;
extern bool opt_debug;  
extern bool opt_debug_diff;
extern bool opt_tracegpu;
extern pthread_mutex_t applog_lock;

// Function declarations  
void applog(int prio, const char *fmt, ...);
void gpulog(int prio, int thr_id, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif // LOGGING_H
