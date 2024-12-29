#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <alloca.h>

// Implementation of logging functions
void applog(int prio, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
    if (use_syslog) {
        va_list ap2;
        char *buf;
        int len;

        /* custom colors to syslog prio */
        if (prio > LOG_DEBUG) {
            switch (prio) {
                case LOG_BLUE: prio = LOG_NOTICE; break;
            }
        }

        va_copy(ap2, ap);
        len = vsnprintf(NULL, 0, fmt, ap2) + 1;
        va_end(ap2);
        buf = (char*) alloca(len);
        if (vsnprintf(buf, len, fmt, ap) >= 0)
            syslog(prio, "%s", buf);
    }
#else
    if (0) {}
#endif
    else {
        const char* color = "";
        const time_t now = time(NULL);
        char *f;
        int len;
        struct tm tm;

        localtime_r(&now, &tm);

        switch (prio) {
            case LOG_ERR:     color = CL_RED; break;
            case LOG_WARNING: color = CL_YLW; break;
            case LOG_NOTICE:  color = CL_WHT; break;
            case LOG_INFO:    color = ""; break;
            case LOG_DEBUG:   color = CL_GRY; break;
            case LOG_BLUE:
                prio = LOG_NOTICE;
                color = CL_CYN;
                break;
        }
        if (!use_colors)
            color = "";

        len = 40 + (int) strlen(fmt) + 2;
        f = (char*) alloca(len);
        sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]%s %s%s\n",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            color,
            fmt,
            use_colors ? CL_N : ""
        );
        if (prio == LOG_RAW) {
            sprintf(f, "%s%s\n", fmt, CL_N);
        }
        pthread_mutex_lock(&applog_lock);
        vfprintf(stdout, f, ap);
        fflush(stdout);
        pthread_mutex_unlock(&applog_lock);
    }
    va_end(ap);
}

void gpulog(int prio, int thr_id, const char *fmt, ...)
{
    char pfmt[128];
    char line[256];
    va_list ap;

    if (prio == LOG_DEBUG && !opt_debug)
        return;

    snprintf(pfmt, sizeof(pfmt), "CPU T%d: Verus Hashing - ", thr_id);

    if (fmt == NULL) {
        snprintf(line, sizeof(line), "%s", pfmt);
    } else {
        va_start(ap, fmt);
        vsnprintf(line, sizeof(line), fmt, ap);
        va_end(ap);
        memmove(line + strlen(pfmt), line, strlen(line) + 1);
        memcpy(line, pfmt, strlen(pfmt));
    }

    if (*line) {
        char *pos = strstr(line, "(null), ");
        if (pos != NULL) {
            memmove(pos, pos + 8, strlen(pos + 8) + 1);
        }
        applog(prio, "%s", line);
    } else {
        fprintf(stderr, "%s OOM!\n", __func__);
    }
}
