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
#include "threading.h" // Add this include

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
int app_exit_code = 0;

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
extern bool get_mininginfo(CURL *curl, struct work *work);
void *longpoll_thread(void *userdata);
// Remove the miner_thread function from here
bool wanna_mine(int thr_id);
void parse_cmdline(int argc, char *argv[]);
void get_currentalgo(char *buf, int sz);
void format_hashrate(double hashrate, char *output);
void cleanup_resources();
void proper_exit(int reason);
bool submit_upstream_work(CURL *curl, struct work *work);
void log_hash_rates(int thr_id, uint64_t loopcnt, time_t *tm_rate_log);
bool handle_stratum_response(char *buf);
void Clear();
bool initialize_curl();
void parse_command_line_arguments(int argc, char *argv[]);
// Remove the entire initialize_mining_threads function definition
// void initialize_mining_threads(int num_threads)
// {
//     // ...existing code...
// }
int main(int argc, char *argv[]);

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

extern bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work);

// Thread management functions

bool wanna_mine(int thr_id)
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
void log_hash_rates(int thr_id, uint64_t loopcnt, time_t *tm_rate_log) {
	if (!opt_quiet && loopcnt > 1 && (time(NULL) - *tm_rate_log) > opt_maxlograte) {
		char s[16];
		format_hashrate(thr_hashrates[thr_id], s);
		if(thr_hashrates[thr_id]>0)
			gpulog(LOG_INFO, thr_id, "%s, %s", device_name[device_map[thr_id % MAX_GPUS]], s);
		*tm_rate_log = time(NULL);
	}
}

void *longpoll_thread(void *userdata)
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

    // Initialize mining threads
    initialize_mining_threads(opt_n_threads); // Add this line

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
