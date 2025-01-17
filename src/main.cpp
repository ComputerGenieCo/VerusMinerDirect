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
#include "pool.h" // Add this include

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
extern bool conditional_pool_rotate; // Change this line

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
// Remove wanna_mine function from here
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
