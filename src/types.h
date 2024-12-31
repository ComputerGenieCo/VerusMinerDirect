#ifndef VERUS_TYPES_H
#define VERUS_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>
#include <pthread.h>
#include <jansson.h>
#include <curl/curl.h>
#include "constants.h"

// Basic type definitions
typedef unsigned char uchar;

// Core mining structures
struct tx {
    uint8_t data[POK_MAX_TX_SZ];
    uint32_t len;
};

struct monitor_info {
    // Hardware monitoring values
    uint32_t gpu_temp;
    uint32_t gpu_fan;
    uint32_t gpu_clock;
    uint32_t gpu_memclock;
    uint32_t gpu_power;
    uint32_t tm_displayed;

    // Synchronization members
    pthread_mutex_t lock;
    pthread_cond_t sampling_signal;
    volatile bool sampling_flag;
};

struct stratum_job {
    // Job identification
    char *job_id;
    unsigned char version[4];
    unsigned char prevhash[32];
    unsigned char ntime[4];
    unsigned char nbits[4];

    // Mining data
    size_t coinbase_size;
    unsigned char *coinbase;
    unsigned char *xnonce2;
    int merkle_count;
    unsigned char **merkle;

    // Job parameters
    double diff;
    uint32_t height;
    uint32_t shares_count;
    bool clean;

    // Extended data
    unsigned char nreward[2];
    unsigned char extra[64];
    unsigned char solution[1344];
};

struct stratum_ctx {
    // Connection info and state
    char *url;
    char *curl_url;
    char *sockbuf;
    char *session_id;
    CURL *curl;
    curl_socket_t sock;
    char curl_err_str[CURL_ERROR_SIZE];

    // Numerical state fields
    size_t sockbuf_size;
    size_t xnonce1_size;
    size_t xnonce2_size;
    int pooln;
    int rpc2;
    int is_equihash;
    int srvtime_diff;
    time_t tm_connected;

    // Active mining data
    struct stratum_job job;
    unsigned char *xnonce1;
    double next_diff;
    double sharediff;
    struct timeval tv_submit;
    uint32_t answer_msec;
};

struct work {
    // Core mining data
    uint32_t data[48];
    uint32_t target[8];
    uint32_t maxvote;
    uint32_t height;

    // Job identification
    char job_id[128];
    size_t xnonce2_len;
    uchar xnonce2[32];

    // Nonce handling
    union {
        uint32_t u32[2];
        uint64_t u64[1];
    } noncerange;
    uint32_t nonces[MAX_NONCES];
    uint8_t valid_nonces;
    uint8_t submit_nonce_id;
    uint8_t job_nonce_id;
    uint8_t pooln;

    // Work metrics 
    double sharediff[MAX_NONCES];
    double shareratio[MAX_NONCES];
    double targetdiff;
    uint32_t scanned_from;
    uint32_t scanned_to;

    // Extended data
    uint32_t tx_count;
    struct tx txs[POK_MAX_TXS];
    uint8_t extra[1388];
    uint8_t solution[1344];
};

struct pool_infos {
    // Core configuration
    uint8_t id;
    uint8_t type;
    uint16_t status;
    int algo;
    char name[64];

    // Connection settings
    uint8_t allow_gbt;
    uint8_t allow_mininginfo;
    uint16_t check_dups;
    int retries;
    int fail_pause;
    int timeout;

    // Credentials
    char url[512];
    char short_url[64];
    char user[192];
    char pass[384];

    // Mining parameters
    double max_diff;
    double max_rate;
    int shares_limit;
    int time_limit;
    int scantime;

    // Runtime state
    struct stratum_ctx stratum;

    // Statistics
    uint32_t work_time;
    uint32_t wait_time;
    uint32_t accepted_count;
    uint32_t rejected_count;
    uint32_t solved_count;
    uint32_t stales_count;
    uint32_t disconnects;
    time_t last_share_time;
    double best_share;
};

struct cgpu_info {
    // Core identifiers
    uint8_t gpu_id;
    uint8_t thr_id;

    // Performance stats
    uint16_t hw_errors;
    unsigned accepted;
    uint32_t rejected;
    double khashes;
    double intensity;
    uint32_t throughput;

    // Device info
    int has_monitoring;
    char gpu_sn[64];
    char gpu_desc[64];

    // Monitoring data
    struct monitor_info monitor;
};

struct thr_info {
    int id;
    pthread_t pth;
    struct thread_q *q;
    struct cgpu_info gpu;
};

struct work_restart {
    /* volatile to modify accross threads (vstudio thing) */
    volatile uint32_t restart;
    char padding[128 - sizeof(uint32_t)];
};

// Workio command types
enum workio_commands {
    WC_GET_WORK,
    WC_SUBMIT_WORK,
    WC_ABORT
};

// Workio command structure  
struct workio_cmd {
    enum workio_commands cmd;
    struct thr_info *thr;
    union {
        struct work *work;
    } u;
    int pooln;
};

// Stats tracking structures
struct stats_data {
    // Core identifiers
    uint8_t thr_id;
    uint8_t gpu_id;
    uint32_t uid;

    // Performance metrics
    double difficulty;
    double hashrate;
    uint32_t hashcount;
    uint32_t globalhashcount;

    // Status info 
    uint32_t height;
    uint32_t tm_stat;
    uint8_t hashfound;
    uint8_t ignored;

    // Pool data
    uint8_t npool;
    uint8_t pool_type;
    uint16_t align;
};

struct hashlog_data {
    // Identifiers
    uint8_t npool;
    uint8_t pool_type; 
    uint8_t nonce_id;
    uint8_t job_nonce_id;

    // Work data
    uint32_t height;
    uint32_t njobid;
    uint32_t nonce;
    double sharediff;

    // Scan range info
    uint32_t scanned_from;
    uint32_t scanned_to;
    uint32_t last_from;

    // Timing data
    uint32_t tm_add;
    uint32_t tm_upd;
    uint32_t tm_sent;
};

struct thread_q;  // Forward declaration

#ifdef __cplusplus
}
#endif

#endif /* VERUS_TYPES_H */
