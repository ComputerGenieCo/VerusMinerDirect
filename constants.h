#ifndef VERUS_CONSTANTS_H
#define VERUS_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

// Program Constants
#define PROGRAM_NAME "ccminer"
#define USER_AGENT PACKAGE_NAME "/" PACKAGE_VERSION

// System Limits
#define MAX_GPUS 140
#define MAX_POOLS 8
#define MAX_NONCES 2
#define POK_MAX_TXS 4 
#define POK_MAX_TX_SZ 16384U

// Exit Codes
#define EXIT_CODE_OK 0
#define EXIT_CODE_USAGE 1  
#define EXIT_CODE_POOL_TIMEOUT 2
#define EXIT_CODE_SW_INIT_ERROR 3
#define EXIT_CODE_CUDA_NODEVICE 4
#define EXIT_CODE_CUDA_ERROR 5
#define EXIT_CODE_TIME_LIMIT 0
#define EXIT_CODE_KILLED 7

// Mining Constants  
#define LP_SCANTIME 60
#define HEAVYCOIN_BLKHDR_SZ 84
#define MNR_BLKHDR_SZ 80
#define EQNONCE_OFFSET 30

// API Constants
#define API_MCAST_CODE "FTW"
#define API_MCAST_ADDR "224.0.0.75"

// Console Colors
#define YES "yes!"
#define YAY "yay!!!"
#define BOO "booooo"

#define CL_N    "\x1B[0m"
#define CL_RED  "\x1B[31m" 
#define CL_GRN  "\x1B[32m"
#define CL_YLW  "\x1B[33m"
#define CL_BLU  "\x1B[34m"
#define CL_MAG  "\x1B[35m"
#define CL_CYN  "\x1B[36m"

#define CL_BLK  "\x1B[22;30m"  /* black */
#define CL_RD2  "\x1B[22;31m"  /* red */
#define CL_GR2  "\x1B[22;32m"  /* green */
#define CL_YL2  "\x1B[22;33m"  /* dark yellow */
#define CL_BL2  "\x1B[22;34m"  /* blue */
#define CL_MA2  "\x1B[22;35m"  /* magenta */
#define CL_CY2  "\x1B[22;36m"  /* cyan */
#define CL_SIL  "\x1B[22;37m"  /* gray */

#ifdef WIN32
#define CL_GRY  "\x1B[01;30m"  /* dark gray */
#else
#define CL_GRY  "\x1B[90m"    /* dark gray selectable in putty */
#endif
#define CL_LRD  "\x1B[01;31m"  /* light red */
#define CL_LGR  "\x1B[01;32m"  /* light green */
#define CL_LYL  "\x1B[01;33m"  /* tooltips */
#define CL_LBL  "\x1B[01;34m"  /* light blue */
#define CL_LMA  "\x1B[01;35m"  /* light magenta */
#define CL_LCY  "\x1B[01;36m"  /* light cyan */
#define CL_WHT  "\x1B[01;37m"  /* white */

// Default Values
#define DEFAULT_SCAN_TIME 10
#define DEFAULT_TIMEOUT 300
#define DEFAULT_RETRY_PAUSE 30
#define DEFAULT_MAX_LOG_RATE 3
#define DEFAULT_API_PORT 4068

// Log Levels (if not defined by syslog.h)
#ifndef LOG_ERR
enum {
    LOG_EMERG   = 0,
    LOG_ALERT   = 1,
    LOG_CRIT    = 2,
    LOG_ERR     = 3,
    LOG_WARNING = 4,
    LOG_NOTICE  = 5,
    LOG_INFO    = 6,
    LOG_DEBUG   = 7
};
#endif

#define LOG_BLUE 0x10
#define LOG_RAW  0x99

// Pool Status Flags
#define POOL_UNUSED 0
#define POOL_GETWORK 1
#define POOL_STRATUM 2
#define POOL_LONGPOLL 4

// Pool Status Management Flags
#define POOL_ST_DEFINED 1
#define POOL_ST_VALID 2  
#define POOL_ST_DISABLED 4
#define POOL_ST_REMOVED 8

#ifdef __cplusplus
}
#endif

#endif /* VERUS_CONSTANTS_H */
