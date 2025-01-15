#define LOGGING_EXTERN

// Standard C/C++ includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/time.h>

// External library includes
#include <curl/curl.h>
#include <openssl/sha.h>

// Platform specific includes
#ifdef WIN32
#include <windows.h>
#include <stdint.h>
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#include "compat/winansi.h"
#else
#include <errno.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#endif
#include <sys/sysctl.h>
#endif
#endif

// Project includes
#include "logging.h"
#include "miner-config.h"
#include "workio.h"
#include "main.h"
#include "signal_handler.h"
#include "constants.h"
#include "config.h"
#include "daemon.h"
#include "verus_stratum.h"  // Add this include

// Global mutex declarations
pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
pthread_mutex_t g_work_lock;
pthread_mutex_t stratum_sock_lock;
pthread_mutex_t stratum_work_lock;

// Global work/mining state
struct work _ALIGN(64) g_work;
volatile time_t g_work_time;
struct work_restart *work_restart = NULL;
double thr_hashrates[MAX_GPUS] = {0};

// Pool related globals
struct pool_infos pools[MAX_POOLS] = {0}; 
struct stratum_ctx stratum = {0};
int num_pools = 1;
volatile int cur_pooln = 0;

// Thread info globals
struct thr_info *thr_info = NULL;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;

// Device related globals
extern const char *opt_algo;
int active_gpus;
bool need_nvsettings = false;
bool need_memclockrst = false;
char *device_name[MAX_GPUS];
short device_map[MAX_GPUS] = {0};
long device_sm[MAX_GPUS] = {0};
short device_mpcount[MAX_GPUS] = {0};
int opt_led_mode = 0;

int device_batchsize[MAX_GPUS] = {0};
int device_texturecache[MAX_GPUS] = {0};
int device_singlememory[MAX_GPUS] = {0};
int parallel = 2;
char *device_config[MAX_GPUS] = {0};
int device_backoff[MAX_GPUS] = {0};
int device_bfactor[MAX_GPUS] = {0};
int device_lookup_gap[MAX_GPUS] = {0};
int device_interactive[MAX_GPUS] = {0};

bool opt_pool_failover = true;
volatile bool pool_on_hold = false;
volatile bool pool_is_switching = false;
volatile int pool_switch_count = 0;
bool conditional_pool_rotate = false;

extern char *opt_scratchpad_url;
extern char *rpc_user;
extern char *rpc_pass;
extern char *rpc_url;
extern char *short_url;
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
struct thr_api *thr_api;
int monitor_thr_id = -1;
volatile bool abort_flag = false;
static int app_exit_code = EXIT_CODE_OK;

uint64_t global_hashrate = 0;
double stratum_diff = 0.0;
double net_diff = 0;
uint64_t net_hashrate = 0;
uint64_t net_blocks = 0;
uint8_t conditional_state[MAX_GPUS] = {0};

extern char *opt_syslog_pfx;
extern char *opt_api_bind;
extern char *opt_api_allow;
extern char *opt_api_groups;
extern char *opt_api_mcast_addr;
extern char *opt_api_mcast_code;
extern char *opt_api_mcast_des;

int cryptonight_fork = 1;

// Forward declarations of functions
extern bool gbt_work_decode(const json_t *val, struct work *work);
static bool get_mininginfo(CURL *curl, struct work *work);
static void *longpoll_thread(void *userdata);
static void *miner_thread(void *userdata);
static bool wanna_mine(int thr_id);
static void affine_to_cpu(int id);
static void affine_to_cpu_mask(int id, unsigned long mask);
static inline void drop_policy(void);
void parse_cmdline(int argc, char *argv[]);
void get_currentalgo(char *buf, int sz);
void format_hashrate(double hashrate, char *output);
void cleanup_resources();
void proper_exit(int reason);
bool submit_upstream_work(CURL *curl, struct work *work);
bool get_upstream_work(CURL *curl, struct work *work);
void restart_threads(void);
void set_thread_priority(int thr_id);
void set_cpu_affinity(int thr_id);
void log_hash_rates(int thr_id, uint64_t loopcnt, time_t *tm_rate_log);
bool handle_stratum_response(char *buf);
void Clear();
void initialize_mutexes();
bool initialize_curl();
void parse_command_line_arguments(int argc, char *argv[]);
void initialize_mining_threads(int num_threads);
int main(int argc, char *argv[]);

// Platform-specific CPU affinity and scheduling functions
#ifdef __linux
#include <sched.h>
static inline void drop_policy(void)
{
    struct sched_param param;
    param.sched_priority = 0;
#ifdef SCHED_IDLE
    if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
        sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

static void affine_to_cpu(int id)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(id, &set);
#if !(defined(__ANDROID__) || (__ANDROID_API__ > 23))
    pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
#else
    sched_setaffinity(0, sizeof(&set), &set);
#endif
}
#elif defined(__FreeBSD__)
#include <sys/cpuset.h>
static inline void drop_policy(void) {}
static void affine_to_cpu(int id)
{
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(id, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#elif defined(WIN32)
static inline void drop_policy(void) {}
static void affine_to_cpu_mask(int id, unsigned long mask)
{
    if (id == -1)
        SetProcessAffinityMask(GetCurrentProcess(), mask);
    else
        SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else
static inline void drop_policy(void) {}
static void affine_to_cpu_mask(int id, uint8_t mask) {}
#endif

// Utility functions for mining operations
void get_currentalgo(char *buf, int sz)
{
    snprintf(buf, sz, "%s", opt_algo);
}

void format_hashrate(double hashrate, char *output)
{
    format_hashrate_unit(hashrate, output, "H/s");
}

// Resource management functions
void cleanup_resources()
{
    pthread_mutex_lock(&stats_lock);
    if (check_dups)
        hashlog_purge_all();
    stats_purge_all();
    pthread_mutex_unlock(&stats_lock);

#ifdef WIN32
    timeEndPeriod(1);
#endif
#ifdef USE_WRAPNVML
    if (hnvml)
    {
        for (int n = 0; n < opt_n_threads && !opt_keep_clocks; n++)
        {
            nvml_reset_clocks(hnvml, device_map[n]);
        }
        nvml_destroy(hnvml);
    }
    if (need_memclockrst)
    {
#ifdef WIN32
        for (int n = 0; n < opt_n_threads && !opt_keep_clocks; n++)
        {
            nvapi_toggle_clocks(n, false);
        }
#endif
    }
#endif
    free(opt_syslog_pfx);
    free(opt_api_bind);
    if (opt_api_allow)
        free(opt_api_allow);
    if (opt_api_groups)
        free(opt_api_groups);
    free(opt_api_mcast_addr);
    free(opt_api_mcast_code);
    free(opt_api_mcast_des);
}

void proper_exit(int reason)
{
    restart_threads();
    if (abort_flag)
        return;

    abort_flag = true;
    usleep(200 * 1000);

    if (reason == EXIT_CODE_OK && app_exit_code != EXIT_CODE_OK)
    {
        reason = app_exit_code;
    }

    cleanup_resources();
    exit(reason);
}

// JSON helper functions

// Network difficulty and work handling functions

// Share submission and result handling

// Block template and mining info functions
bool gbt_work_decode(const json_t *val, struct work *work)
{
    json_t *err = json_object_get(val, "error");
    if (err && !json_is_null(err))
    {
        allow_gbt = false;
        applog(LOG_INFO, "GBT not supported, block height unavailable");
        return false;
    }

    if (!work->height)
    {
        json_t *key = json_object_get(val, "height");
        if (key && json_is_integer(key))
        {
            work->height = (uint32_t)json_integer_value(key);
            if (!opt_quiet && work->height > g_work.height)
            {
                if (net_diff > 0.)
                {
                    char netinfo[64] = {0};
                    char srate[32] = {0};
                    snprintf(netinfo, sizeof(netinfo), "diff %.2f", net_diff);
                    if (net_hashrate)
                    {
                        format_hashrate((double)net_hashrate, srate);
                        strcat(netinfo, ", net ");
                        strcat(netinfo, srate);
                    }
                    applog(LOG_BLUE, "%s block %d, %s",
                           opt_algo, work->height, netinfo);
                }
                else
                {
                    applog(LOG_BLUE, "%s %s block %d", short_url,
                           opt_algo, work->height);
                }
                g_work.height = work->height;
            }
        }
    }

    return true;
}

static bool get_mininginfo(CURL *curl, struct work *work)
{
    struct pool_infos *pool = &pools[work->pooln];
    int curl_err = 0;

    if (have_stratum || have_longpoll || !allow_mininginfo)
        return false;

    json_t *val = json_rpc_call_pool(curl, pool, info_req, false, false, &curl_err);

    if (!val && curl_err == -1)
    {
        allow_mininginfo = false;
        if (opt_debug)
        {
            applog(LOG_DEBUG, "getmininginfo not supported");
        }
        return false;
    }
    else
    {
        json_t *res = json_object_get(val, "result");
        if (res)
        {
            json_t *key = json_object_get(res, "difficulty");
            if (key)
            {
                if (json_is_object(key))
                    key = json_object_get(key, "proof-of-work");
                if (json_is_real(key))
                    net_diff = json_real_value(key);
            }
            key = json_object_get(res, "networkhashps");
            if (key && json_is_integer(key))
            {
                net_hashrate = json_integer_value(key);
            }
            key = json_object_get(res, "netmhashps");
            if (key && json_is_real(key))
            {
                net_hashrate = (uint64_t)(json_real_value(key) * 1e6);
            }
            key = json_object_get(res, "blocks");
            if (key && json_is_integer(key))
            {
                net_blocks = json_integer_value(key);
            }
        }
    }
    json_decref(val);
    return true;
}

bool get_upstream_work(CURL *curl, struct work *work)
{
    bool rc = false;
    struct timeval tv_start, tv_end, diff;
    struct pool_infos *pool = &pools[work->pooln];
    const char *rpc_req = json_rpc_getwork;
    json_t *val;

    gettimeofday(&tv_start, NULL);

    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s: want_longpoll=%d have_longpoll=%d",
               __func__, want_longpoll, have_longpoll);

    val = json_rpc_call_pool(curl, pool, rpc_req, want_longpoll, have_longpoll, NULL);
    gettimeofday(&tv_end, NULL);

    if (have_stratum || unlikely(work->pooln != cur_pooln))
    {
        if (val)
            json_decref(val);
        return false;
    }

    if (!val)
        return false;

    rc = work_decode(json_object_get(val, "result"), work);

    if (opt_protocol && rc)
    {
        timeval_subtract(&diff, &tv_end, &tv_start);
        applog(LOG_DEBUG, "got new work in %.2f ms",
               (1000.0 * diff.tv_sec) + (0.001 * diff.tv_usec));
    }

    json_decref(val);

    get_mininginfo(curl, work);
    get_blocktemplate(curl, work);

    return rc;
}

bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
{
    uchar merkle_root[64] = {0};
    int i;

    if (!sctx->job.job_id)
    {
        return false;
    }

    pthread_mutex_lock(&stratum_work_lock);

    snprintf(work->job_id, sizeof(work->job_id), "%07x %s",
             be32dec(sctx->job.ntime) & 0xfffffff, sctx->job.job_id);
    work->xnonce2_len = sctx->xnonce2_size;
    memcpy(work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size);

    work->height = sctx->job.height;
    work->pooln = sctx->pooln;

    for (i = 0; i < sctx->job.merkle_count; i++)
    {
        memcpy(merkle_root + 32, sctx->job.merkle[i], 32);
    }

    for (i = 0; i < (int)sctx->xnonce2_size && !++sctx->job.xnonce2[i]; i++)
        ;

    memset(work->data, 0, sizeof(work->data));
    work->data[0] = le32dec(sctx->job.version);
    for (i = 0; i < 8; i++)
        work->data[1 + i] = le32dec((uint32_t *)sctx->job.prevhash + i);

    memcpy(&work->data[9], sctx->job.coinbase, 32 + 32);
    work->data[25] = le32dec(sctx->job.ntime);
    work->data[26] = le32dec(sctx->job.nbits);
    memcpy(&work->solution, sctx->job.solution, 1344);
    memcpy(&work->data[27], sctx->xnonce1, sctx->xnonce1_size & 0x1F);
    work->data[35] = 0x80;

    if (opt_showdiff || opt_max_diff > 0.)
        calc_network_diff(work);

    pthread_mutex_unlock(&stratum_work_lock);

    if (opt_difficulty == 0.)
        opt_difficulty = 1.;

    memcpy(work->target, sctx->job.extra, 32);
    work->targetdiff = (sctx->job.diff / opt_difficulty);

    if (stratum_diff != sctx->job.diff)
    {
        char sdiff[32] = {0};
        stratum_diff = sctx->job.diff;
        if (opt_showdiff && work->targetdiff != stratum_diff)
            snprintf(sdiff, 32, " (%.5f)", work->targetdiff);
        applog(LOG_BLUE, "Stratum difficulty set to %.0f%s", stratum_diff, sdiff);
    }

    return true;
}

// Thread management functions
void restart_threads(void)
{
    if (opt_debug && !opt_quiet)
        applog(LOG_DEBUG, "%s", __FUNCTION__);

    for (int i = 0; i < opt_n_threads && work_restart; i++)
        work_restart[i].restart = 1;
}

static bool wanna_mine(int thr_id)
{
    bool state = true;
    bool allow_pool_rotate = (thr_id == 0 && num_pools > 1 && !pool_is_switching);

    if (opt_max_temp > 0.0)
    {
#ifdef USE_WRAPNVML
        struct cgpu_info *cgpu = &thr_info[thr_id].gpu;
        float temp = gpu_temp(cgpu);
        if (temp > opt_max_temp)
        {
            if (!conditional_state[thr_id] && !opt_quiet)
                gpulog(LOG_INFO, thr_id, "temperature too high (%.0f°c), waiting...", temp);
            state = false;
        }
        else if (opt_max_temp > 0. && opt_resume_temp > 0. && conditional_state[thr_id] && temp > opt_resume_temp)
        {
            if (!thr_id && opt_debug)
                applog(LOG_DEBUG, "temperature did not reach resume value %.1f...", opt_resume_temp);
            state = false;
        }
#endif
    }
    if (opt_max_diff > 0.0 && net_diff > opt_max_diff)
    {
        int next = pool_get_first_valid(cur_pooln + 1);
        if (num_pools > 1 && pools[next].max_diff != pools[cur_pooln].max_diff && opt_resume_diff <= 0.)
            conditional_pool_rotate = allow_pool_rotate;
        if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
            applog(LOG_INFO, "network diff too high, waiting...");
        state = false;
    }
    else if (opt_max_diff > 0. && opt_resume_diff > 0. && conditional_state[thr_id] && net_diff > opt_resume_diff)
    {
        if (!thr_id && opt_debug)
            applog(LOG_DEBUG, "network diff did not reach resume value %.3f...", opt_resume_diff);
        state = false;
    }
    if (opt_max_rate > 0.0 && net_hashrate > opt_max_rate)
    {
        int next = pool_get_first_valid(cur_pooln + 1);
        if (pools[next].max_rate != pools[cur_pooln].max_rate && opt_resume_rate <= 0.)
            conditional_pool_rotate = allow_pool_rotate;
        if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
        {
            char rate[32];
            format_hashrate(opt_max_rate, rate);
            applog(LOG_INFO, "network hashrate too high, waiting %s...", rate);
        }
        state = false;
    }
    else if (opt_max_rate > 0. && opt_resume_rate > 0. && conditional_state[thr_id] && net_hashrate > opt_resume_rate)
    {
        if (!thr_id && opt_debug)
            applog(LOG_DEBUG, "network rate did not reach resume value %.3f...", opt_resume_rate);
        state = false;
    }
    conditional_state[thr_id] = (uint8_t)!state;
    return state;
}

// Mining thread implementations
void set_thread_priority(int thr_id)
{
    if (opt_priority > 0)
    {
        int prio = 2;
#ifndef WIN32
        prio = 0;
        switch (opt_priority)
        {
        case 0:
            prio = 15;
            break;
        case 1:
            prio = 5;
            break;
        case 2:
            prio = 0;
            break;
        case 3:
            prio = -1;
            break;
        case 4:
            prio = -10;
            break;
        case 5:
            prio = -15;
        }
        if (opt_debug)
            applog(LOG_DEBUG, "Thread %d priority %d (nice %d)",
                   thr_id, opt_priority, prio);
#endif
        setpriority(PRIO_PROCESS, 0, prio);
        drop_policy();
    }
}

void set_cpu_affinity(int thr_id)
{
    if (num_cpus > 1)
    {
        affine_to_cpu(thr_id);
    }
}

void log_hash_rates(int thr_id, uint64_t loopcnt, time_t *tm_rate_log) {
	if (!opt_quiet && loopcnt > 1 && (time(NULL) - *tm_rate_log) > opt_maxlograte) {
		char s[16];
		format_hashrate(thr_hashrates[thr_id], s);
		if(thr_hashrates[thr_id]>0)
			gpulog(LOG_INFO, thr_id, "%s, %s", device_name[device_map[thr_id % MAX_GPUS]], s);
		*tm_rate_log = time(NULL);
	}
}

static void *miner_thread(void *userdata)
{
    struct thr_info *mythr = (struct thr_info *)userdata;
    int switchn = pool_switch_count;
    int thr_id = mythr->id;
    int dev_id = device_map[thr_id % MAX_GPUS];
    struct cgpu_info *cgpu = &thr_info[thr_id].gpu;
    struct work work;
    uint64_t loopcnt = 0;
    uint32_t max_nonce;
    uint32_t end_nonce = UINT32_MAX / opt_n_threads * (thr_id + 1) - (thr_id + 1);
    time_t tm_rate_log = 0;
    bool work_done = false;
    bool extrajob = false;
    char s[16];
    int rc = 0;

    memset(&work, 0, sizeof(work));

    set_thread_priority(thr_id);
    set_cpu_affinity(thr_id);

    if (num_cpus > 1)
    {
        affine_to_cpu(thr_id);
    }

    while (!abort_flag)
    {
        struct timeval tv_start, tv_end, diff;
        unsigned long hashes_done;
        uint32_t start_nonce;
        uint32_t scan_time = have_longpoll ? LP_SCANTIME : opt_scantime;
        uint64_t max64, minmax = 0x100000;
        int nodata_check_oft = 0;
        bool regen = false;

        int wcmplen = 76;
        int wcmpoft = 0;

        uint32_t *nonceptr = (uint32_t *)(((char *)work.data) + wcmplen);

        nonceptr = &work.data[EQNONCE_OFFSET];
        wcmplen = 4 + 32 + 32;

        if (have_stratum)
        {
            uint32_t sleeptime = 0;

            while (!work_done && time(NULL) >= (g_work_time + opt_scantime))
            {
                usleep(100 * 1000);
                if (sleeptime > 4)
                {
                    extrajob = true;
                    break;
                }
                sleeptime++;
            }
            if (sleeptime && opt_debug && !opt_quiet)
                applog(LOG_DEBUG, "sleeptime: %u ms", sleeptime * 100);
            pthread_mutex_lock(&g_work_lock);
            extrajob |= work_done;

            regen = (nonceptr[0] >= end_nonce);
            regen = regen || extrajob;

            if (regen)
            {
                work_done = false;
                extrajob = false;
                if (stratum_gen_work(&stratum, &g_work))
                    g_work_time = time(NULL);
            }
        }
        else
        {
            uint32_t secs = 0;
            pthread_mutex_lock(&g_work_lock);
            secs = (uint32_t)(time(NULL) - g_work_time);
            if (secs >= scan_time || nonceptr[0] >= (end_nonce - 0x100))
            {
                if (opt_debug && g_work_time && !opt_quiet)
                    applog(LOG_DEBUG, "work time %u/%us nonce %x/%x", secs, scan_time, nonceptr[0], end_nonce);
                if (unlikely(!get_work(mythr, &g_work)))
                {
                    pthread_mutex_unlock(&g_work_lock);
                    if (switchn != pool_switch_count)
                    {
                        switchn = pool_switch_count;
                        continue;
                    }
                    else
                    {
                        applog(LOG_ERR, "work retrieval failed, exiting mining thread %d", mythr->id);
                        goto out;
                    }
                }
                g_work_time = time(NULL);
            }
        }

        if (strcmp(work.job_id, g_work.job_id))
            stratum.job.shares_count = 0;

        if (!opt_benchmark && (g_work.height != work.height || memcmp(work.target, g_work.target, sizeof(work.target))))
        {
            if (opt_debug)
            {
                uint64_t target64 = g_work.target[7] * 0x100000000ULL + g_work.target[6];
                applog(LOG_DEBUG, "job %s target change: %llx (%.1f)", g_work.job_id, target64, g_work.targetdiff);
            }
            memcpy(work.target, g_work.target, sizeof(work.target));
            work.targetdiff = g_work.targetdiff;
            work.height = g_work.height;
        }

        if (memcmp(&work.data[wcmpoft], &g_work.data[wcmpoft], wcmplen))
        {
            memcpy(&work, &g_work, sizeof(struct work));
            nonceptr[0] = (UINT32_MAX / opt_n_threads) * thr_id;
        }
        else
            nonceptr[0]++;

        struct timeval tv;
        gettimeofday(&tv, NULL);
        
        uint32_t timestamp = (uint32_t)(tv.tv_sec ^ tv.tv_usec);
        uint32_t random_bits = (rand() & 0xFF) | ((rand() & 0xFF) << 8);
        nonceptr[2] = (timestamp & 0xFFFF0000) | (random_bits << 8) | (thr_id & 0xFF);

        pthread_mutex_unlock(&g_work_lock);

        loopcnt++;

        nodata_check_oft = 0;
        if (have_stratum && work.data[nodata_check_oft] == 0 && !opt_benchmark)
        {
            sleep(1);
            if (!thr_id)
                pools[cur_pooln].wait_time += 1;
            gpulog(LOG_DEBUG, thr_id, "no data");
            continue;
        }

        if (!wanna_mine(thr_id))
        {
            if (num_pools > 1 && conditional_pool_rotate)
            {
                if (!pool_is_switching)
                    pool_switch_next(thr_id);
                else if (time(NULL) - firstwork_time > 35)
                {
                    if (!opt_quiet)
                        applog(LOG_WARNING, "Pool switching timed out...");
                    if (!thr_id)
                        pools[cur_pooln].wait_time += 1;
                    pool_is_switching = false;
                }
                sleep(1);
                continue;
            }

            pool_on_hold = true;
            global_hashrate = 0;
            sleep(5);
            if (!thr_id)
                pools[cur_pooln].wait_time += 5;
            continue;
        }
        else
        {
        }

        pool_on_hold = false;

        work_restart[thr_id].restart = 0;

        if (have_stratum)
            max64 = LP_SCANTIME;
        else
            max64 = max(1, (int64_t)scan_time + g_work_time - time(NULL));

        if (opt_time_limit > 0 && firstwork_time)
        {
            int passed = (int)(time(NULL) - firstwork_time);
            int remain = (int)(opt_time_limit - passed);
            if (remain < 0)
            {
                if (thr_id != 0)
                {
                    sleep(1);
                    continue;
                }
                if (num_pools > 1 && pools[cur_pooln].time_limit > 0)
                {
                    if (!pool_is_switching)
                    {
                        if (!opt_quiet)
                            applog(LOG_INFO, "Pool mining timeout of %ds reached, rotate...", opt_time_limit);
                        pool_switch_next(thr_id);
                    }
                    else if (passed > 35)
                    {
                        applog(LOG_WARNING, "Pool switch to %d timed out...", cur_pooln);
                        if (!thr_id)
                            pools[cur_pooln].wait_time += 1;
                        pool_is_switching = false;
                    }
                    sleep(1);
                    continue;
                }
                app_exit_code = EXIT_CODE_TIME_LIMIT;
                abort_flag = true;
                if (opt_benchmark)
                {
                    char rate[32];
                    format_hashrate((double)global_hashrate, rate);
                    applog(LOG_NOTICE, "Benchmark: %s", rate);
                    usleep(200 * 1000);
                    fprintf(stderr, "%llu\n", (long long unsigned int)global_hashrate);
                }
                else
                {
                    applog(LOG_NOTICE, "Mining timeout of %ds reached, exiting...", opt_time_limit);
                }
                workio_abort();
                break;
            }
            if (remain < max64)
                max64 = remain;
        }

        if (opt_shares_limit > 0 && firstwork_time)
        {
            int64_t shares = (pools[cur_pooln].accepted_count + pools[cur_pooln].rejected_count);
            if (shares >= opt_shares_limit)
            {
                int passed = (int)(time(NULL) - firstwork_time);
                if (thr_id != 0)
                {
                    sleep(1);
                    continue;
                }
                if (num_pools > 1 && pools[cur_pooln].shares_limit > 0)
                {
                    if (!pool_is_switching)
                    {
                        if (!opt_quiet)
                            applog(LOG_INFO, "Pool shares limit of %d reached, rotate...", opt_shares_limit);
                        pool_switch_next(thr_id);
                    }
                    else if (passed > 35)
                    {
                        applog(LOG_WARNING, "Pool switch to %d timed out...", cur_pooln);
                        if (!thr_id)
                            pools[cur_pooln].wait_time += 1;
                        pool_is_switching = false;
                    }
                    sleep(1);
                    continue;
                }
                abort_flag = true;
                app_exit_code = EXIT_CODE_OK;
                applog(LOG_NOTICE, "Mining limit of %d shares reached, exiting...", opt_shares_limit);
                workio_abort();
                break;
            }
        }

        max64 *= (uint32_t)thr_hashrates[thr_id];

        if (max64 < minmax)
        {
            max64 = max(minmax - 1, max64);
        }

        max64 = min(UINT32_MAX, max64);

        start_nonce = nonceptr[0];

        if (end_nonce >= UINT32_MAX - 256)
            end_nonce = UINT32_MAX;

        if ((max64 + start_nonce) >= end_nonce)
            max_nonce = end_nonce;
        else
            max_nonce = (uint32_t)(max64 + start_nonce);

        if (unlikely(start_nonce > max_nonce))
        {
            max_nonce = end_nonce = UINT32_MAX;
        }

        work.scanned_from = start_nonce;

        gettimeofday(&tv_start, NULL);
        rc = scan_for_valid_hashes(thr_id, &work, max_nonce, &hashes_done);
        gettimeofday(&tv_end, NULL);

        if (abort_flag)
            break;

        if (work_restart[thr_id].restart)
            continue;

        timeval_subtract(&diff, &tv_end, &tv_start);

        if (cgpu && diff.tv_sec)
        {
            cgpu->monitor.sampling_flag = false;
        }

        if (diff.tv_usec || diff.tv_sec)
        {
            double dtime = (double)diff.tv_sec + 1e-6 * diff.tv_usec;

            double rate_factor = 1.0;

            if (dtime > 0.0)
            {
                pthread_mutex_lock(&stats_lock);
                thr_hashrates[thr_id] = hashes_done / dtime;
                thr_hashrates[thr_id] *= rate_factor;
                if (loopcnt > 2)
                    stats_remember_speed(thr_id, hashes_done, thr_hashrates[thr_id], (uint8_t)rc, work.height);
                pthread_mutex_unlock(&stats_lock);
            }
        }

        if (rc > 0)
            work.scanned_to = work.nonces[0];
        if (rc > 1)
            work.scanned_to = max(work.nonces[0], work.nonces[1]);
        else
        {
            work.scanned_to = max_nonce;
            if (opt_debug && opt_benchmark)
            {
                gpulog(LOG_DEBUG, thr_id, "ends=%08x range=%08x", nonceptr[0], (nonceptr[0] - start_nonce));
            }
            if (nonceptr[0] > UINT32_MAX - 64)
                nonceptr[0] = UINT32_MAX;
        }

        log_hash_rates(thr_id, loopcnt, &tm_rate_log);

        if (firstwork_time && thr_id == (opt_n_threads - 1))
        {
            double hashrate = 0.;
            pthread_mutex_lock(&stats_lock);
            for (int i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
                hashrate += stats_get_speed(i, thr_hashrates[i]);
            pthread_mutex_unlock(&stats_lock);
            if (opt_benchmark && loopcnt > 2)
            {
                format_hashrate(hashrate, s);
                applog(LOG_NOTICE, "Total: %s", s);
            }

            pools[cur_pooln].work_time = (uint32_t)(time(NULL) - firstwork_time);

            global_hashrate = llround(hashrate);
        }

        if (firstwork_time == 0)
            firstwork_time = time(NULL);

        if (cgpu)
            cgpu->accepted += work.valid_nonces;

        if (rc > 0 && !opt_benchmark)
        {
            uint32_t curnonce = nonceptr[0];

            work.submit_nonce_id = 0;
            nonceptr[0] = work.nonces[0];
            if (!submit_work(mythr, &work))
                break;
            nonceptr[0] = curnonce;

            if (!have_stratum && !have_longpoll)
            {
                pthread_mutex_lock(&g_work_lock);
                g_work_time = 0;
                pthread_mutex_unlock(&g_work_lock);
                continue;
            }

            if (rc > 1 && work.nonces[1])
            {
                work.submit_nonce_id = 1;
                nonceptr[0] = work.nonces[1];
                if (!submit_work(mythr, &work))
                    break;
                nonceptr[0] = curnonce;
                work.nonces[1] = 0;
            }
        }
    }

out:

    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() died", __func__);
    tq_freeze(mythr->q);
    return NULL;
}

static void *longpoll_thread(void *userdata)
{
    struct thr_info *mythr = (struct thr_info *)userdata;
    struct pool_infos *pool;
    CURL *curl = NULL;
    char *hdr_path = NULL, *lp_url = NULL;
    const char *rpc_req = json_rpc_getwork;
    bool need_slash = false;
    int pooln, switchn;

    curl = curl_easy_init();
    if (unlikely(!curl))
    {
        applog(LOG_ERR, "%s() CURL init failed", __func__);
        goto out;
    }

wait_lp_url:
    hdr_path = (char *)tq_pop(mythr->q, NULL);
    if (!hdr_path)
        goto out;

    if (!(pools[cur_pooln].type & POOL_STRATUM))
    {
        pooln = cur_pooln;
        pool = &pools[pooln];
    }
    else
    {
        have_stratum = true;
    }

    switchn = pool_switch_count;

    if (strstr(hdr_path, "://"))
    {
        lp_url = hdr_path;
        hdr_path = NULL;
    }
    else
    {
        char *copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
        if (rpc_url[strlen(rpc_url) - 1] != '/')
            need_slash = true;

        lp_url = (char *)malloc(strlen(rpc_url) + strlen(copy_start) + 2);
        if (!lp_url)
            goto out;

        snprintf(lp_url, strlen(rpc_url) + strlen(copy_start) + 2, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
    }

    if (!pool_is_switching)
        applog(LOG_BLUE, "Long-polling on %s", lp_url);

    pool_is_switching = false;

longpoll_retry:

    while (!abort_flag)
    {
        json_t *val = NULL, *soval;
        int err = 0;

        if (opt_debug_threads)
            applog(LOG_DEBUG, "longpoll %d: %d count %d %d, switching=%d, have_stratum=%d",
                   pooln, cur_pooln, switchn, pool_switch_count, pool_is_switching, have_stratum);

        if (switchn != pool_switch_count)
            goto need_reinit;

        val = json_rpc_longpoll(curl, lp_url, pool, rpc_req, &err);
        if (have_stratum || switchn != pool_switch_count)
        {
            if (val)
                json_decref(val);
            goto need_reinit;
        }
        if (likely(val))
        {
            soval = json_object_get(json_object_get(val, "result"), "submitold");
            submit_old = soval ? json_is_true(soval) : false;
            pthread_mutex_lock(&g_work_lock);
            if (work_decode(json_object_get(val, "result"), &g_work))
            {
                restart_threads();
                if (!opt_quiet)
                {
                    char netinfo[64] = {0};
                    if (net_diff > 0.)
                    {
                        snprintf(netinfo, sizeof(netinfo), "diff %.3f", net_diff);
                    }
                    if (opt_showdiff)
                    {
                        snprintf(&netinfo[strlen(netinfo)], sizeof(netinfo) - strlen(netinfo), ", target %.3f", g_work.targetdiff);
                    }
                    if (g_work.height)
                        applog(LOG_BLUE, "%s block %u%s", opt_algo, g_work.height, netinfo);
                    else
                        applog(LOG_BLUE, "%s detected new block%s", short_url, netinfo);
                }
                g_work_time = time(NULL);
            }
            pthread_mutex_unlock(&g_work_lock);
            json_decref(val);
        }
        else
        {
            g_work_time = 0;
            if (err != CURLE_OPERATION_TIMEDOUT)
            {
                if (opt_debug_threads)
                    applog(LOG_DEBUG, "%s() err %d, retry in %s seconds",
                           __func__, err, opt_fail_pause);
                sleep(opt_fail_pause);
                goto longpoll_retry;
            }
        }
    }

out:
    have_longpoll = false;
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() died", __func__);

    free(hdr_path);
    free(lp_url);
    tq_freeze(mythr->q);
    if (curl)
        curl_easy_cleanup(curl);

    return NULL;

need_reinit:
    have_longpoll = false;
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() reinit...", __func__);
    if (hdr_path)
        free(hdr_path);
    hdr_path = NULL;
    if (lp_url)
        free(lp_url);
    lp_url = NULL;
    goto wait_lp_url;
}

// GUI/Terminal management functions
void Clear()
{
#if defined _WIN32
    system("cls");
#elif defined(__LINUX__) || defined(__gnu_linux__) || defined(__linux__)
    system("clear");
#elif defined(__APPLE__)
    system("clear");
#endif
}

// Core initialization functions
void initialize_mutexes()
{
    pthread_mutex_init(&applog_lock, NULL);
    pthread_mutex_init(&stratum_sock_lock, NULL);
    pthread_mutex_init(&stratum_work_lock, NULL);
    pthread_mutex_init(&stats_lock, NULL);
    pthread_mutex_init(&g_work_lock, NULL);
}

bool initialize_curl()
{
    long flags = !opt_benchmark && strncmp(rpc_url, "https:", 6)
                     ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
                     : CURL_GLOBAL_ALL;
    if (curl_global_init(flags))
    {
        applog(LOG_ERR, "CURL initialization failed");
        return false;
    }
    return true;
}

// Command line and configuration parsing functions 
void parse_command_line_arguments(int argc, char *argv[])
{
    int key;

    while (1)
    {
#if HAVE_GETOPT_LONG
        key = getopt_long(argc, argv, short_options, options, NULL);
#else
        key = getopt(argc, argv, short_options);
#endif
        if (key < 0)
            break;

        parse_arg(key, optarg);
    }
    if (optind < argc)
    {
        fprintf(stderr, "%s: unsupported non-option argument '%s' (see --help)\n",
                argv[0], argv[optind]);
    }

    parse_config(opt_config);

    if (opt_vote == 9999)
    {
        opt_vote = 0;
    }
}

// Thread and worker initialization functions
void initialize_mining_threads(int num_threads)
{
    struct thr_info *thr;
    int i;

    work_restart = (struct work_restart *)calloc(num_threads, sizeof(*work_restart));
    if (!work_restart)
        exit(EXIT_CODE_SW_INIT_ERROR);

    thr_info = (struct thr_info *)calloc(num_threads + 5, sizeof(*thr));
    if (!thr_info)
        exit(EXIT_CODE_SW_INIT_ERROR);

    longpoll_thr_id = num_threads + 1;
    thr = &thr_info[longpoll_thr_id];
    thr->id = longpoll_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        exit(EXIT_CODE_SW_INIT_ERROR);

    if (unlikely(pthread_create(&thr->pth, NULL, longpoll_thread, thr)))
    {
        applog(LOG_ERR, "longpoll thread create failed");
        exit(EXIT_CODE_SW_INIT_ERROR);
    }

    stratum_thr_id = num_threads + 2;
    thr = &thr_info[stratum_thr_id];
    thr->id = stratum_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        exit(EXIT_CODE_SW_INIT_ERROR);

    if (unlikely(pthread_create(&thr->pth, NULL, stratum_thread, thr)))
    {
        applog(LOG_ERR, "stratum thread create failed");
        exit(EXIT_CODE_SW_INIT_ERROR);
    }

    work_thr_id = num_threads;
    thr = &thr_info[work_thr_id];
    thr->id = work_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        exit(EXIT_CODE_SW_INIT_ERROR);

    if (pthread_create(&thr->pth, NULL, workio_thread, thr))
    {
        applog(LOG_ERR, "workio thread create failed");
        exit(EXIT_CODE_SW_INIT_ERROR);
    }

    if (want_stratum && have_stratum)
    {
        tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
    }

    if (opt_api_port)
    {
        api_thr_id = num_threads + 3;
        thr = &thr_info[api_thr_id];
        thr->id = api_thr_id;
        thr->q = tq_new();
        if (!thr->q)
            exit(EXIT_CODE_SW_INIT_ERROR);

        if (unlikely(pthread_create(&thr->pth, NULL, api_thread, thr)))
        {
            applog(LOG_ERR, "api thread create failed");
            exit(EXIT_CODE_SW_INIT_ERROR);
        }
    }

    for (i = 0; i < num_threads; i++)
    {
        thr = &thr_info[i];

        thr->id = i;
        thr->gpu.thr_id = i;
        thr->gpu.gpu_id = (uint8_t)device_map[i];
        thr->q = tq_new();
        if (!thr->q)
            exit(EXIT_CODE_SW_INIT_ERROR);

        pthread_mutex_init(&thr->gpu.monitor.lock, NULL);
        pthread_cond_init(&thr->gpu.monitor.sampling_signal, NULL);

        if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr)))
        {
            applog(LOG_ERR, "thread %d create failed", i);
            exit(EXIT_CODE_SW_INIT_ERROR);
        }
    }

    applog(LOG_INFO, "%d miner thread%s started, using '%s' algorithm.",
           num_threads, num_threads > 1 ? "s" : "", opt_algo);
}

// Main application entry point and initialization
int main(int argc, char *argv[])
{
    struct thr_info *thr;
    long flags;
    int i;

    init_config_defaults();

    parse_single_opt('q', argc, argv);

    Clear();
    printf("*************************************************************\n");
    printf("*  " PROGRAM_NAME " CPU: " PACKAGE_VERSION " for Verushash v2.2.2 based on ccminer *\n");
    printf("*************************************************************\n");

    printf("Originally based on Christian Buchner and Christian H. project\n");
    printf("Adapted to Verus by Monkins1010\n");
    printf("Goto https://wiki.verus.io/#!index.md for mining setup guides. \n");
    printf("Git repo located at: " PACKAGE_URL " \n\n");

    rpc_user = strdup("");
    rpc_pass = strdup("");
    rpc_url = strdup("");


    initialize_mutexes();

#if defined(WIN32)
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    num_cpus = sysinfo.dwNumberOfProcessors;
#elif defined(_SC_NPROCESSORS_CONF)
    num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
    int req[] = {CTL_HW, HW_NCPU};
    size_t len = sizeof(num_cpus);
    sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
    num_cpus = 1;
#endif
    if (num_cpus < 1)
        num_cpus = 1;

    active_gpus = 1;

    for (i = 0; i < MAX_GPUS; i++)
    {
        device_map[i] = i % active_gpus;
        device_name[i] = NULL;
        device_config[i] = NULL;
        device_backoff[i] = is_windows() ? 12 : 2;
        device_bfactor[i] = is_windows() ? 11 : 0;
        device_lookup_gap[i] = 1;
        device_batchsize[i] = 1024;
        device_interactive[i] = -1;
        device_texturecache[i] = -1;
        device_singlememory[i] = -1;
    }

    parse_command_line_arguments(argc, argv);

    if (!opt_benchmark && !strlen(rpc_url))
    {
        char defconfig[MAX_PATH] = {0};
        get_defconfig_path(defconfig, MAX_PATH, argv[0]);
        if (strlen(defconfig))
        {
            if (opt_debug)
                applog(LOG_DEBUG, "Using config %s", defconfig);
            parse_arg('c', defconfig);
            parse_command_line_arguments(argc, argv);
        }
    }

    if (!strlen(rpc_url))
    {
        if (!opt_benchmark)
        {
            fprintf(stderr, "%s: no URL supplied\n", argv[0]);
            show_usage_and_exit(1);
        }
        pool_set_creds(0);
    }

    memset(&stratum.url, 0, sizeof(stratum));

    pool_init_defaults();

    if (opt_debug)
        pool_dump_infos();
    cur_pooln = pool_get_first_valid(0);
    pool_switch(-1, cur_pooln);

    opt_extranonce = false;

    if (!initialize_curl())
    {
        return EXIT_CODE_SW_INIT_ERROR;
    }

    if (opt_background)
    {
#ifndef WIN32
        i = fork();
        if (i < 0)
            proper_exit(EXIT_CODE_SW_INIT_ERROR);
        if (i > 0)
            proper_exit(EXIT_CODE_OK);
        i = setsid();
        if (i < 0)
            applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
        i = chdir("/");
        if (i < 0)
            applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
        setup_signal_handlers();
#else
        HWND hcon = GetConsoleWindow();
        if (hcon)
        {
            ShowWindow(hcon, SW_HIDE);
        }
        else
        {
            HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
            CloseHandle(h);
            FreeConsole();
        }
#endif
    }

    setup_signal_handlers();

    if (opt_priority > 0)
    {
#ifndef WIN32
        int prio = 0;
        switch (opt_priority)
        {
        case 0:
            prio = 15;
            break;
        case 1:
            prio = 5;
            break;
        case 2:
            prio = 0;
            break;
        case 3:
            prio = -1;
            break;
        case 4:
            prio = -10;
            break;
        case 5:
            prio = -15;
        }
        setpriority(PRIO_PROCESS, 0, prio);
        drop_policy();
#else
        DWORD prio = NORMAL_PRIORITY_CLASS;
        switch (opt_priority)
        {
        case 1:
            prio = BELOW_NORMAL_PRIORITY_CLASS;
            break;
        case 2:
            prio = NORMAL_PRIORITY_CLASS;
            break;
        case 3:
            prio = ABOVE_NORMAL_PRIORITY_CLASS;
            break;
        case 4:
            prio = HIGH_PRIORITY_CLASS;
            break;
        case 5:
            prio = REALTIME_PRIORITY_CLASS;
        }
        SetPriorityClass(GetCurrentProcess(), prio);
        SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED);
        timeBeginPeriod(1);
#endif
    }

    if (active_gpus == 0)
    {
        applog(LOG_ERR, "No CUDA devices found! terminating.");
        exit(1);
    }
    if (!opt_n_threads)
        opt_n_threads = active_gpus;
    else if (active_gpus > opt_n_threads)
        active_gpus = opt_n_threads;

    gpu_threads = max(gpu_threads, opt_n_threads / active_gpus);

    initialize_mining_threads(opt_n_threads);

    pthread_join(thr_info[work_thr_id].pth, NULL);

    abort_flag = true;

    for (i = 0; i < opt_n_threads; i++)
    {
        struct cgpu_info *cgpu = &thr_info[i].gpu;
        if (monitor_thr_id != -1 && cgpu)
        {
            pthread_cond_signal(&cgpu->monitor.sampling_signal);
        }
        pthread_join(thr_info[i].pth, NULL);
    }

    if (monitor_thr_id != -1)
    {
        pthread_join(thr_info[monitor_thr_id].pth, NULL);
    }

    if (opt_debug)
        applog(LOG_DEBUG, "workio thread dead, exiting.");

    proper_exit(EXIT_CODE_OK);
    return 0;
}
