#ifndef VERUS_CONSTANTS_H
#define VERUS_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/*********************
 * Core Definitions  *
 *********************/

// Program Version & Identity
#define PROTOCOL_VERSION 170002
#define API_VERSION "1.9"
#define PROGRAM_NAME "VerusMiner"
#define USER_AGENT PACKAGE_NAME "/" PACKAGE_VERSION

// Resource Limits & Sizes 
#define VERUS_MAX_SIZE 0x02000000  // Changed from MAX_SIZE to VERUS_MAX_SIZE
#define MAX_GPUS 140
#define MAX_POOLS 8
#define MAX_NONCES 2
#define MYBUFSIZ 16384
#define SOCK_REC_BUFSZ 1024
#define QUEUE 10

/************************
 * Mining Configuration *
 ************************/

// Block Header Constants
#define HEAVYCOIN_BLKHDR_SZ 84
#define MNR_BLKHDR_SZ 80
#define EQNONCE_OFFSET 30
#define POK_MAX_TXS 4
#define POK_MAX_TX_SZ 16384U

// Performance & Stats
#define STATS_AVG_SAMPLES 30
#define STATS_PURGE_TIMEOUT (120*60) /* 120 minutes */
#define LOG_PURGE_TIMEOUT (5*60)
#define LP_SCANTIME 60

// Hashrate Display Units
#define HASHRATE_MED_DIVISOR 1000.0
#define HASHRATE_HIGH_DIVISOR 1000000.0 
#define HASHRATE_VERY_HIGH_DIVISOR 1000000000.0
#define HASHRATE_ULTRA_HIGH_DIVISOR 1000000000000.0

/***********************
 * Network & Protocol *
 ***********************/

// Socket Definitions
#define SOCKETTYPE long
#define SOCKETFAIL(a) ((a) < 0)
#define INVSOCK -1
#define INVINETADDR -1
#define CLOSESOCKET close
#define SOCKETINIT {}
#define SOCKERRMSG strerror(errno)

// Network Addresses
#define ALLIP4 "0.0.0.0"
#define ALLIPS "0/0"
#define LOCAL_ADDRESS "127.0.0.1"

// API Configuration
#define API_MCAST_CODE "FTW"
#define API_MCAST_ADDR "224.0.0.75"
#define API_UNAVAILABLE " - API will not be available"
#define API_MCAST_UNAVAILABLE " - API multicast listener will not be available"
#define DEFAULT_API_PORT 4068

// RPC Constants
#define CURL_ERR_STR_SIZE CURL_ERROR_SIZE
#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

/*******************
 * Pool Management *
 *******************/

// Pool Types
#define POOL_UNUSED 0
#define POOL_GETWORK 1
#define POOL_STRATUM 2
#define POOL_LONGPOLL 4

// Pool States
#define POOL_ST_DEFINED 1
#define POOL_ST_VALID 2
#define POOL_ST_DISABLED 4
#define POOL_ST_REMOVED 8

// Default Timeouts
#define DEFAULT_SCAN_TIME 10
#define DEFAULT_TIMEOUT 300
#define DEFAULT_RETRY_PAUSE 30
#define DEFAULT_MAX_LOG_RATE 3

/*********************
 * Logging & Output *
 *********************/

// Exit Codes
#define EXIT_CODE_OK 0
#define EXIT_CODE_USAGE 1
#define EXIT_CODE_POOL_TIMEOUT 2
#define EXIT_CODE_SW_INIT_ERROR 3
#define EXIT_CODE_CUDA_NODEVICE 4
#define EXIT_CODE_CUDA_ERROR 5
#define EXIT_CODE_TIME_LIMIT 0
#define EXIT_CODE_KILLED 7

// Log Levels
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

// Console Messages
#define YES "yes!"
#define YAY "yay!!!"
#define BOO "booooo"

// Basic Console Colors
#define CL_N    "\x1B[0m"
#define CL_RED  "\x1B[31m"
#define CL_GRN  "\x1B[32m"
#define CL_YLW  "\x1B[33m"
#define CL_BLU  "\x1B[34m"
#define CL_MAG  "\x1B[35m"
#define CL_CYN  "\x1B[36m"

// Extended Console Colors
#define CL_BLK  "\x1B[22;30m"  /* black */
#define CL_RD2  "\x1B[22;31m"  /* red */
#define CL_GR2  "\x1B[22;32m"  /* green */
#define CL_YL2  "\x1B[22;33m"  /* dark yellow */
#define CL_BL2  "\x1B[22;34m"  /* blue */
#define CL_MA2  "\x1B[22;35m"  /* magenta */
#define CL_CY2  "\x1B[22;36m"  /* cyan */
#define CL_SIL  "\x1B[22;37m"  /* gray */

// Platform-Specific Colors
#ifdef WIN32
#define CL_GRY  "\x1B[01;30m"  /* dark gray */
#else
#define CL_GRY  "\x1B[90m"     /* dark gray selectable in putty */
#endif

// Light Console Colors
#define CL_LRD  "\x1B[01;31m"  /* light red */
#define CL_LGR  "\x1B[01;32m"  /* light green */
#define CL_LYL  "\x1B[01;33m"  /* tooltips */
#define CL_LBL  "\x1B[01;34m"  /* light blue */
#define CL_LMA  "\x1B[01;35m"  /* light magenta */
#define CL_LCY  "\x1B[01;36m"  /* light cyan */
#define CL_WHT  "\x1B[01;37m"  /* white */

/***********************
 * Hashlog Constants   *
 ***********************/
#define HI_DWORD(u64) ((uint32_t) (u64 >> 32))
#define LO_DWORD(u64) ((uint32_t) u64)
#define MK_HI64(u32) (0x100000000ULL * u32)

// Configuration Options 
#define CFG_NULL 0
#define CFG_POOL 1

// JSON Options
#define JSON_ID_INIT 0x0150E828

// NVAPI Constants
#define NVAPI_ID_IFVERSION 0x01053FA5
#define NVAPI_ID_PERF_INFO 0x409D9841
#define NVAPI_ID_PERF_STATS 0x3D358A0C
#define NVAPI_ID_POWER_INFO 0x34206D86
#define NVAPI_ID_POWERPOL_GET 0x70916171
#define NVAPI_ID_POWERPOL_SET 0xAD95F5ED
#define NVAPI_ID_POWERTOPO_GET 0xEDCF624E
#define NVAPI_ID_THERMAL_INFO 0x0D258BB5
#define NVAPI_ID_TLIMIT_GET 0xE9C425A1
#define NVAPI_ID_TLIMIT_SET 0x34C0B13D
#define NVAPI_ID_SERIALNUM_GET 0x14B83A5F
#define NVAPI_ID_VOLTAGE_GET 0x465F9BCF
#define NVAPI_ID_VOLT_STATUS_GET 0xC16C7E2C
#define NVAPI_ID_VOLTAGE 0x28766157
#define NVAPI_ID_CLK_RANGE_GET 0x64B43A6A
#define NVAPI_ID_CLK_BOOST_MASK 0x507B4B59
#define NVAPI_ID_CLK_BOOST_TABLE_GET 0x23F1B133
#define NVAPI_ID_CLK_BOOST_TABLE_SET 0x0733E009
#define NVAPI_ID_VFP_CURVE_GET 0x21537AD4
#define NVAPI_ID_CURVE_GET 0xE440B867
#define NVAPI_ID_CURVE_SET 0x39442CFB
#define NVAPI_ID_VOLTBOOST_GET 0x9DF23CA1
#define NVAPI_ID_VOLTBOOST_SET 0xB9306D9B
#define NVAPI_ID_PERFCLOCKS_GET 0x1EA54A3B
#define NVAPI_ID_PERFCLOCKS_SET 0x07BCF4AC
#define NVAPI_ID_PSTATELIMITS_GET 0x88C82104
#define NVAPI_ID_PSTATELIMITS_SET 0xFDFC7D49
#define NVAPI_ID_PSTATE20_SET 0x0F4DAE6B
#define NVAPI_ID_VOLTAGES 0x7D656244
#define NVAPI_ID_COOLERSETTINGS 0xDA141340
#define NVAPI_ID_COOLER_SETLEVELS 0x891FA0AE
#define NVAPI_ID_COOLER_RESTORE 0x8F6ED0FB
#define NVAPI_ID_I2CREADEX 0x4D7B0709
#define NVAPI_ID_I2CWRITEEX 0x283AC65A
#define NVAPI_ID_UNLOAD 0xD22BDD7E

#ifdef __cplusplus
}
#endif

#endif /* VERUS_CONSTANTS_H */
