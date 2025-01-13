#ifndef LOGGING_H
#define LOGGING_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "constants.h"

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

// Global variables declarations
extern bool use_syslog;
extern bool use_colors;
extern bool opt_debug;  // Added missing opt_debug declaration
extern pthread_mutex_t applog_lock;
extern char *opt_syslog_pfx;

// Function declarations
void applog(int prio, const char *fmt, ...);
void gpulog(int prio, int thr_id, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif // LOGGING_H
