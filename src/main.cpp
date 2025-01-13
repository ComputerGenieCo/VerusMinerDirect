#define LOGGING_EXTERN
#include "logging.h"
#include <miner-config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <curl/curl.h>
#include <openssl/sha.h>
#include "workio.h"

#ifdef WIN32
#include <windows.h>
#include <stdint.h>
#else
#include <errno.h>
#include <sys/resource.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

#include "miner-config.h"
#include "types.h"
#include "main.h"
#include "signal_handler.h"
#include "constants.h"
#include "logging.h"

#ifdef WIN32
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#include "compat/winansi.h"
BOOL WINAPI ConsoleHandler(DWORD);
#endif

pthread_mutex_t applog_lock;
pthread_mutex_t stats_lock;
pthread_mutex_t g_work_lock;
pthread_mutex_t stratum_sock_lock;
pthread_mutex_t stratum_work_lock;

struct work _ALIGN(64) g_work;
volatile time_t g_work_time;
struct work_restart *work_restart = NULL;
double thr_hashrates[MAX_GPUS] = {0};

struct pool_infos pools[MAX_POOLS] = {0}; 
struct stratum_ctx stratum = {0};
int num_pools = 1;
volatile int cur_pooln = 0;

struct thr_info *thr_info = NULL;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;

bool opt_debug = false;
bool opt_debug_diff = false;
bool opt_debug_threads = false;
bool opt_protocol = false;
bool opt_benchmark = false;
bool opt_showdiff = true;
bool opt_hwmonitor = false;

bool want_longpoll = false;
bool have_longpoll = false;
bool want_stratum = true;
bool have_stratum = false;
bool allow_gbt = true;
bool allow_mininginfo = true;
bool check_dups = false;
bool check_stratum_jobs = false;
bool opt_submit_stale = false;
bool submit_old = false;
bool use_syslog = false;
bool use_colors = true;
int use_pok = 0;
int use_roots = 0;
static bool opt_background = false;
bool opt_quiet = false;
int opt_maxlograte = 3;
int opt_fail_pause = 30;
int opt_retries = -1;
int opt_time_limit = -1;
int opt_shares_limit = -1;
time_t firstwork_time = 0;
int opt_timeout = 300;
int opt_scantime = 10;
static json_t *opt_config;
static const bool opt_time = true;
extern const char *opt_algo;
const char *opt_algo = "ALGO_EQUIHASH";
int opt_n_threads = 0;
int gpu_threads = 1;
int64_t opt_affinity = -1L;
int opt_priority = 0;
static double opt_difficulty = 1.;
bool opt_extranonce = true;
bool opt_trust_pool = false;
uint16_t opt_vote = 9999;
int num_cpus;
int active_gpus;
bool need_nvsettings = false;
bool need_memclockrst = false;
char *device_name[MAX_GPUS];
short device_map[MAX_GPUS] = {0};
long device_sm[MAX_GPUS] = {0};
short device_mpcount[MAX_GPUS] = {0};
int opt_led_mode = 0;
int opt_cudaschedule = -1;
static bool opt_keep_clocks = false;

int device_batchsize[MAX_GPUS] = {0};
int device_texturecache[MAX_GPUS] = {0};
int device_singlememory[MAX_GPUS] = {0};
int parallel = 2;
char *device_config[MAX_GPUS] = {0};
int device_backoff[MAX_GPUS] = {0};
int device_bfactor[MAX_GPUS] = {0};
int device_lookup_gap[MAX_GPUS] = {0};
int device_interactive[MAX_GPUS] = {0};
int opt_nfactor = 0;
bool opt_autotune = true;

bool opt_pool_failover = true;
volatile bool pool_on_hold = false;
volatile bool pool_is_switching = false;
volatile int pool_switch_count = 0;
bool conditional_pool_rotate = false;

extern char *opt_scratchpad_url;

char *rpc_user = NULL;
char *rpc_pass;
char *rpc_url;
char *short_url = NULL;

char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_api *thr_api;
int monitor_thr_id = -1;
bool stratum_need_reset = false;
volatile bool abort_flag = false;
static int app_exit_code = EXIT_CODE_OK;

uint64_t global_hashrate = 0;
double stratum_diff = 0.0;
double net_diff = 0;
uint64_t net_hashrate = 0;
uint64_t net_blocks = 0;
uint8_t conditional_state[MAX_GPUS] = {0};
double opt_max_temp = 0.0;
double opt_max_diff = -1.;
double opt_max_rate = -1.;
double opt_resume_temp = 0.;
double opt_resume_diff = 0.;
double opt_resume_rate = -1.;

int opt_statsavg = 30;

static char *opt_syslog_pfx = strdup(PROGRAM_NAME);
char *opt_api_bind = strdup("127.0.0.1");
int opt_api_port = 4068;
char *opt_api_allow = NULL;
char *opt_api_groups = NULL;
bool opt_api_mcast = false;
char *opt_api_mcast_addr = strdup(API_MCAST_ADDR);
char *opt_api_mcast_code = strdup(API_MCAST_CODE);
char *opt_api_mcast_des = strdup("");
int opt_api_mcast_port = 4068;

bool opt_stratum_stats = false;

int cryptonight_fork = 1;

static char const usage[] = "\
Usage: " PROGRAM_NAME " [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the hash algorithm to use\n\
			verus       Veruscoin\n\
  -d, --devices         Comma separated list of CUDA devices to use.\n\
                        Device IDs start counting from 0! Alternatively takes\n\
                        string names of your cards like gtx780ti or gt640#2\n\
                        (matching 2nd gt640 in the PC)\n\
  -i  --intensity=N[,N] GPU intensity 8.0-25.0 (default: auto) \n\
                        Decimals are allowed for fine tuning \n\
      --cuda-schedule   Set device threads scheduling mode (default: auto)\n\
  -f, --diff-factor     Divide difficulty by this factor (default 1.0) \n\
  -m, --diff-multiplier Multiply difficulty by this value (default 1.0) \n\
  -o, --url=URL         URL of mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of nVidia GPUs)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
  -R, --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
      --shares-limit    maximum shares [s] to mine before exiting the program.\n\
      --time-limit      maximum time [s] to mine before exiting the program.\n\
  -T, --timeout=N       network timeout, in seconds (default: 300)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 10)\n\
      --submit-stale    ignore stale jobs checks, may create more rejected shares\n\
  -n, --ndevs           list cuda devices\n\
  -N, --statsavg        number of samples used to compute hashrate (default: 30)\n\
      --no-gbt          disable getblocktemplate support (height check in solo)\n\
      --no-longpoll     disable X-Long-Polling support\n\
      --no-stratum      disable X-Stratum support\n\
      --no-extranonce   disable extranonce subscribe on stratum\n\
  -q, --quiet           disable per-thread hashmeter output\n\
      --no-color        disable colored output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n\
      --cpu-affinity    set process affinity to cpu core(s), mask 0x3 for cores 0 and 1\n\
      --cpu-priority    set process priority (default: 3) 0 idle, 2 normal to 5 highest\n\
  -b, --api-bind=port   IP:port for the miner API (default: 127.0.0.1:4068), 0 disabled\n\
      --api-remote      Allow remote control, like pool switching, imply --api-allow=0/0\n\
      --api-allow=...   IP/mask of the allowed api client(s), 0/0 for all\n\
      --max-temp=N      Only mine if gpu temp is less than specified value\n\
      --max-rate=N[KMG] Only mine if net hashrate is less than specified value\n\
      --max-diff=N      Only mine if net difficulty is less than specified value\n\
                        Can be tuned with --resume-diff=N to set a resume value\n\
      --max-log-rate    Interval to reduce per gpu hashrate logs (default: 3)\n"
#if defined(__linux)
                            "\
      --mem-clock=3505  Set the gpu memory max clock (346.72+ driver)\n\
      --gpu-clock=1150  Set the gpu engine max clock (346.72+ driver)\n\
      --pstate=0[,2]    Set the gpu power state (352.21+ driver)\n\
      --plimit=100W     Set the gpu power limit (352.21+ driver)\n"
#else
                            "\
      --mem-clock=3505  Set the gpu memory boost clock\n\
      --mem-clock=+500  Set the gpu memory offset\n\
      --gpu-clock=1150  Set the gpu engine boost clock\n\
      --plimit=100      Set the gpu power limit in percentage\n\
      --tlimit=80       Set the gpu thermal limit in degrees\n\
      --led=100         Set the logo led level (0=disable, 0xFF00FF for RVB)\n"
#endif
#ifdef HAVE_SYSLOG_H
                            "\
  -S, --syslog          use system log for output messages\n\
      --syslog-prefix=... allow to change syslog tool name\n"
#endif
                            "\
      --hide-diff       hide submitted block and net difficulty (old mode)\n\
  -B, --background      run the miner in the background\n\
      --benchmark       run in offline benchmark mode\n\
      --cputest         debug hashes from cpu algorithms\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
  -V, --version         display version information and exit\n\
  -h, --help            display this help text and exit\n\
";

static char const short_options[] =
#ifdef HAVE_SYSLOG_H
    "S"
#endif
    "a:Bc:i:Dhp:Px:f:m:nqr:R:s:t:T:o:u:O:Vd:N:b:l:L:";

struct option options[] = {
    {"algo", 1, NULL, 'a'},
    {"api-bind", 1, NULL, 'b'},
    {"api-remote", 0, NULL, 1030},
    {"api-allow", 1, NULL, 1031},
    {"api-groups", 1, NULL, 1032},
    {"api-mcast", 0, NULL, 1033},
    {"api-mcast-addr", 1, NULL, 1034},
    {"api-mcast-code", 1, NULL, 1035},
    {"api-mcast-port", 1, NULL, 1036},
    {"api-mcast-des", 1, NULL, 1037},
    {"background", 0, NULL, 'B'},
    {"benchmark", 0, NULL, 1005},
    {"cert", 1, NULL, 1001},
    {"config", 1, NULL, 'c'},
    {"cputest", 0, NULL, 1006},
    {"cpu-affinity", 1, NULL, 1020},
    {"cpu-priority", 1, NULL, 1021},
    {"cuda-schedule", 1, NULL, 1025},
    {"debug", 0, NULL, 'D'},
    {"help", 0, NULL, 'h'},
    {"intensity", 1, NULL, 'i'},
    {"ndevs", 0, NULL, 'n'},
    {"no-color", 0, NULL, 1002},
    {"no-extranonce", 0, NULL, 1012},
    {"no-gbt", 0, NULL, 1011},
    {"no-longpoll", 0, NULL, 1003},
    {"no-stratum", 0, NULL, 1007},
    {"max-temp", 1, NULL, 1060},
    {"max-diff", 1, NULL, 1061},
    {"max-rate", 1, NULL, 1062},
    {"resume-diff", 1, NULL, 1063},
    {"resume-rate", 1, NULL, 1064},
    {"resume-temp", 1, NULL, 1065},
    {"pass", 1, NULL, 'p'},
    {"pool-name", 1, NULL, 1100},
    {"pool-algo", 1, NULL, 1101},
    {"pool-scantime", 1, NULL, 1102},
    {"pool-shares-limit", 1, NULL, 1109},
    {"pool-time-limit", 1, NULL, 1108},
    {"pool-max-diff", 1, NULL, 1161},
    {"pool-max-rate", 1, NULL, 1162},
    {"pool-disabled", 1, NULL, 1199},
    {"protocol-dump", 0, NULL, 'P'},
    {"proxy", 1, NULL, 'x'},
    {"quiet", 0, NULL, 'q'},
    {"retries", 1, NULL, 'r'},
    {"retry-pause", 1, NULL, 'R'},
    {"scantime", 1, NULL, 's'},
    {"show-diff", 0, NULL, 1013},
    {"submit-stale", 0, NULL, 1015},
    {"hide-diff", 0, NULL, 1014},
    {"statsavg", 1, NULL, 'N'},
    {"gpu-clock", 1, NULL, 1070},
    {"mem-clock", 1, NULL, 1071},
    {"pstate", 1, NULL, 1072},
    {"plimit", 1, NULL, 1073},
    {"keep-clocks", 0, NULL, 1074},
    {"tlimit", 1, NULL, 1075},
    {"led", 1, NULL, 1080},
    {"max-log-rate", 1, NULL, 1019},
#ifdef HAVE_SYSLOG_H
    {"syslog", 0, NULL, 'S'},
    {"syslog-prefix", 1, NULL, 1018},
#endif
    {"shares-limit", 1, NULL, 1009},
    {"time-limit", 1, NULL, 1008},
    {"threads", 1, NULL, 't'},
    {"vote", 1, NULL, 1022},
    {"trust-pool", 0, NULL, 1023},
    {"timeout", 1, NULL, 'T'},
    {"url", 1, NULL, 'o'},
    {"user", 1, NULL, 'u'},
    {"userpass", 1, NULL, 'O'},
    {"version", 0, NULL, 'V'},
    {"devices", 1, NULL, 'd'},
    {"diff-multiplier", 1, NULL, 'm'},
    {"diff-factor", 1, NULL, 'f'},
    {0, 0, 0, 0}};

int options_count()
{
    int n = 0;
    while (options[n].name != NULL)
        n++;
    return n;
}

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

static void parse_cmdline(int argc, char *argv[]);
static bool get_blocktemplate(CURL *curl, struct work *work);
static void *stratum_thread(void *userdata);
static void *longpoll_thread(void *userdata);

void get_currentalgo(char *buf, int sz)
{
    snprintf(buf, sz, "%s", opt_algo);
}

void format_hashrate(double hashrate, char *output)
{
    format_hashrate_unit(hashrate, output, "H/s");
}

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

bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen)
{
    const char *hexstr;
    json_t *tmp;

    tmp = json_object_get(obj, key);
    if (unlikely(!tmp))
    {
        applog(LOG_ERR, "JSON key '%s' not found", key);
        return false;
    }
    hexstr = json_string_value(tmp);
    if (unlikely(!hexstr))
    {
        applog(LOG_ERR, "JSON key '%s' is not a string", key);
        return false;
    }
    if (!hex2bin((uchar *)buf, hexstr, buflen))
        return false;

    return true;
}

static void calc_network_diff(struct work *work)
{
    net_diff = verus_network_diff(work);
    return;
}

static bool work_decode(const json_t *val, struct work *work)
{
    int data_size, target_size = sizeof(work->target);
    int adata_sz, atarget_sz = ARRAY_SIZE(work->target);
    int i;

    data_size = 128;
    adata_sz = data_size / 4;

    if (!jobj_binary(val, "data", work->data, data_size))
    {
        json_t *obj = json_object_get(val, "data");
        int len = obj ? (int)strlen(json_string_value(obj)) : 0;
        if (!len || len > sizeof(work->data) * 2)
        {
            applog(LOG_ERR, "JSON invalid data (len %d <> %d)", len / 2, data_size);
            return false;
        }
        else
        {
            data_size = len / 2;
            if (!jobj_binary(val, "data", work->data, data_size))
            {
                applog(LOG_ERR, "JSON invalid data (len %d)", data_size);
                return false;
            }
        }
    }

    if (!jobj_binary(val, "target", work->target, target_size))
    {
        applog(LOG_ERR, "JSON invalid target");
        return false;
    }

    work->maxvote = 0;

    for (i = 0; i < adata_sz; i++)
        work->data[i] = le32dec(work->data + i);
    for (i = 0; i < atarget_sz; i++)
        work->target[i] = le32dec(work->target + i);

    if ((opt_showdiff || opt_max_diff > 0.) && !allow_mininginfo)
        calc_network_diff(work);

    work->targetdiff = target_to_diff(work->target);

    stratum_diff = work->targetdiff;

    work->tx_count = use_pok = 0;

    cbin2hex(work->job_id, (const char *)&work->data[17], 4);

    return true;
}

int share_result(int result, int pooln, double sharediff, const char *reason)
{
    const char *flag;
    char suppl[32] = {0};
    char solved[16] = {0};
    char s[32] = {0};
    double hashrate = 0.;
    struct pool_infos *p = &pools[pooln];

    pthread_mutex_lock(&stats_lock);
    for (int i = 0; i < opt_n_threads; i++)
    {
        hashrate += stats_get_speed(i, thr_hashrates[i]);
    }
    pthread_mutex_unlock(&stats_lock);

    result ? p->accepted_count++ : p->rejected_count++;

    p->last_share_time = time(NULL);
    if (sharediff > p->best_share)
        p->best_share = sharediff;

    global_hashrate = llround(hashrate);

    format_hashrate(hashrate, s);
    if (opt_showdiff)
        snprintf(suppl, sizeof(suppl), "diff %.3f", sharediff);
    else
        snprintf(suppl, sizeof(suppl), "%.2f%%", 100. * p->accepted_count / (p->accepted_count + p->rejected_count));

    if (!net_diff || sharediff < net_diff)
    {
        flag = use_colors ? (result ? CL_GRN YES : CL_RED BOO)
                          : (result ? "(" YES ")" : "(" BOO ")");
    }
    else
    {
        p->solved_count++;
        flag = use_colors ? (result ? CL_GRN YAY : CL_RED BOO)
                          : (result ? "(" YAY ")" : "(" BOO ")");
        snprintf(solved, sizeof(solved), " solved: %u", p->solved_count);
    }

    applog(LOG_NOTICE, "accepted: %lu/%lu (%s), %s %s%s",
           p->accepted_count,
           p->accepted_count + p->rejected_count,
           suppl, s, flag, solved);
    if (reason)
    {
        applog(LOG_BLUE, "reject reason: %s", reason);
        if (!check_dups && strncasecmp(reason, "duplicate", 9) == 0)
        {
            applog(LOG_WARNING, "enabling duplicates check feature");
            check_dups = true;
            g_work_time = 0;
        }
    }
    return 1;
}

bool submit_upstream_work(CURL *curl, struct work *work)
{
    char s[512];
    struct pool_infos *pool = &pools[work->pooln];
    json_t *val, *res, *reason;
    bool stale_work = false;
    int idnonce = work->submit_nonce_id;

    if (pool->type & POOL_STRATUM && stratum.is_equihash)
    {
        struct work submit_work;
        memcpy(&submit_work, work, sizeof(struct work));
        if (equi_stratum_submit(pool, &submit_work))
            hashlog_remember_submit(&submit_work, submit_work.nonces[idnonce]);
        stratum.job.shares_count++;
        return true;
    }

    stale_work = work->height && work->height < g_work.height;
    if (have_stratum && !stale_work && !opt_submit_stale)
    {
        pthread_mutex_lock(&g_work_lock);
        if (strlen(work->job_id + 8))
            stale_work = strncmp(work->job_id + 8, g_work.job_id + 8, sizeof(g_work.job_id) - 8);
        if (stale_work)
        {
            pool->stales_count++;
            if (opt_debug)
                applog(LOG_DEBUG, "outdated job %s, new %s stales=%d",
                       work->job_id + 8, g_work.job_id + 8, pool->stales_count);
            if (!check_stratum_jobs && pool->stales_count > 5)
            {
                if (!opt_quiet)
                    applog(LOG_WARNING, "Enabled stratum stale jobs workaround");
                check_stratum_jobs = true;
            }
        }
        pthread_mutex_unlock(&g_work_lock);
    }

    if (!have_stratum && !stale_work && allow_gbt)
    {
        struct work wheight = {0};
        if (get_blocktemplate(curl, &wheight))
        {
            if (work->height && work->height < wheight.height)
            {
                if (opt_debug)
                    applog(LOG_WARNING, "block %u was already solved", work->height);
                return true;
            }
        }
    }

    if (!submit_old && stale_work)
    {
        if (opt_debug)
            applog(LOG_WARNING, "stale work detected, discarding");
        return true;
    }

    if (pool->type & POOL_STRATUM)
    {
        uint32_t sent = 0;
        uint32_t ntime, nonce = work->nonces[idnonce];
        char *ntimestr, *noncestr, *xnonce2str;

        le32enc(&ntime, work->data[17]);
        le32enc(&nonce, work->data[19]);
        noncestr = bin2hex((const uchar *)(&nonce), 4);

        if (check_dups)
            sent = hashlog_already_submittted(work->job_id, nonce);
        if (sent > 0)
        {
            sent = (uint32_t)time(NULL) - sent;
            if (!opt_quiet)
            {
                applog(LOG_WARNING, "nonce %s was already sent %u seconds ago", noncestr, sent);
                hashlog_dump_job(work->job_id);
            }
            free(noncestr);
            g_work_time = 0;
            restart_threads();
            return true;
        }

        ntimestr = bin2hex((const uchar *)(&ntime), 4);

        xnonce2str = bin2hex(work->xnonce2, work->xnonce2_len);

        stratum.sharediff = work->sharediff[idnonce];

        if (net_diff && stratum.sharediff > net_diff && (opt_debug || opt_debug_diff))
            applog(LOG_INFO, "share diff: %.5f, possible block found!!!",
                   stratum.sharediff);
        else if (opt_debug_diff)
            applog(LOG_DEBUG, "share diff: %.5f (x %.1f)",
                   stratum.sharediff, work->shareratio[idnonce]);

        snprintf(s, sizeof(s), "{\"method\": \"mining.submit\", \"params\": ["
                   "\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":%u}",
                pool->user, work->job_id + 8, xnonce2str, ntimestr, noncestr, stratum.job.shares_count + 10);

        free(xnonce2str);
        free(ntimestr);
        free(noncestr);

        gettimeofday(&stratum.tv_submit, NULL);
        if (unlikely(!stratum_send_line(&stratum, s)))
        {
            applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
            return false;
        }

        if (check_dups || opt_showdiff)
            hashlog_remember_submit(work, nonce);
        stratum.job.shares_count++;
    }
    else
    {
        int data_size = 128;
        int adata_sz = data_size / sizeof(uint32_t);

        char *str = NULL;

        for (int i = 0; i < adata_sz; i++)
        {
            le32enc(work->data + i, work->data[i]);
        }
        str = bin2hex((uchar *)work->data, data_size);
        if (unlikely(!str))
        {
            applog(LOG_ERR, "submit_upstream_work OOM");
            return false;
        }

        snprintf(s, sizeof(s),
                "{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":10}\r\n",
                str);

        val = json_rpc_call_pool(curl, pool, s, false, false, NULL);
        if (unlikely(!val))
        {
            applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
            return false;
        }

        res = json_object_get(val, "result");
        reason = json_object_get(val, "reject-reason");
        if (!share_result(json_is_true(res), work->pooln, work->sharediff[0],
                          reason ? json_string_value(reason) : NULL))
        {
            if (check_dups)
                hashlog_purge_job(work->job_id);
        }

        json_decref(val);

        free(str);
    }

    return true;
}

static bool gbt_work_decode(const json_t *val, struct work *work)
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

#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"
static const char *gbt_req =
    "{\"method\": \"getblocktemplate\", \"params\": [{"
    "}], \"id\":9}\r\n";

static bool get_blocktemplate(CURL *curl, struct work *work)
{
    struct pool_infos *pool = &pools[work->pooln];
    if (!allow_gbt)
        return false;

    int curl_err = 0;
    json_t *val = json_rpc_call_pool(curl, pool, gbt_req, false, false, &curl_err);

    if (!val && curl_err == -1)
    {
        allow_gbt = false;
        if (!opt_quiet)
        {
            applog(LOG_BLUE, "gbt not supported, block height notices disabled");
        }
        return false;
    }

    bool rc = gbt_work_decode(json_object_get(val, "result"), work);

    json_decref(val);

    return rc;
}

static const char *info_req =
    "{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

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

static const char *json_rpc_getwork =
    "{\"method\":\"getwork\",\"params\":[],\"id\":0}\r\n";

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

static bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work)
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

    //equi_work_set_target(work, sctx->job.diff / opt_difficulty);
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

        // Get high precision timestamp for entropy
        struct timeval tv;
        gettimeofday(&tv, NULL);
        
        // Mix thread ID, timestamp and random bits for unique nonce initialization
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

    pool->type |= POOL_LONGPOLL;

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

bool handle_stratum_response(char *buf)
{
    json_t *val, *err_val, *res_val, *id_val;
    json_error_t err;
    struct timeval tv_answer, diff;
    int num = 0, job_nonce_id = 0;
    double sharediff = stratum.sharediff;
    bool ret = false;

    val = JSON_LOADS(buf, &err);
    if (!val)
    {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");
    id_val = json_object_get(val, "id");

    if (!id_val || json_is_null(id_val))
        goto out;

    num = (int)json_integer_value(id_val);
    if (num < 4)
        goto out;

    job_nonce_id = num - 10;
    if (opt_showdiff && check_dups)
        sharediff = hashlog_get_sharediff(g_work.job_id, job_nonce_id, sharediff);

    gettimeofday(&tv_answer, NULL);
    timeval_subtract(&diff, &tv_answer, &stratum.tv_submit);
    stratum.answer_msec = (1000 * diff.tv_sec) + (uint32_t)(0.001 * diff.tv_usec);

    if (!res_val)
        goto out;
    share_result(json_is_true(res_val), stratum.pooln, sharediff,
                 err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

    ret = true;
out:
    if (val)
        json_decref(val);

    return ret;
}

static void *stratum_thread(void *userdata)
{
    struct thr_info *mythr = (struct thr_info *)userdata;
    struct pool_infos *pool;
    stratum_ctx *ctx = &stratum;
    int pooln, switchn;
    char *s;

wait_stratum_url:
    stratum.url = (char *)tq_pop(mythr->q, NULL);
    if (!stratum.url)
        goto out;

    if (!pool_is_switching)
        applog(LOG_BLUE, "Starting on %s", stratum.url);

    ctx->pooln = pooln = cur_pooln;
    switchn = pool_switch_count;
    pool = &pools[pooln];

    pool_is_switching = false;
    stratum_need_reset = false;

    while (!abort_flag)
    {
        int failures = 0;

        if (stratum_need_reset)
        {
            stratum_need_reset = false;
            if (stratum.url)
                stratum_disconnect(&stratum);
            else
                stratum.url = strdup(pool->url);
        }

        while (!stratum.curl && !abort_flag)
        {
            pthread_mutex_lock(&g_work_lock);
            g_work_time = 0;
            g_work.data[0] = 0;
            pthread_mutex_unlock(&g_work_lock);
            restart_threads();

            if (!stratum_connect(&stratum, pool->url) ||
                !stratum_subscribe(&stratum) ||
                !stratum_authorize(&stratum, pool->user, pool->pass))
            {
                stratum_disconnect(&stratum);
                if (opt_retries >= 0 && ++failures > opt_retries)
                {
                    if (num_pools > 1 && opt_pool_failover)
                    {
                        applog(LOG_WARNING, "Stratum connect timeout, failover...");
                        pool_switch_next(-1);
                    }
                    else
                    {
                        applog(LOG_ERR, "...terminating workio thread");
                        workio_abort();
                        proper_exit(EXIT_CODE_POOL_TIMEOUT);
                        goto out;
                    }
                }
                if (switchn != pool_switch_count)
                    goto pool_switched;
                if (!opt_benchmark)
                    applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
                sleep(opt_fail_pause);
            }
        }

        if (switchn != pool_switch_count)
            goto pool_switched;

        if (stratum.job.job_id &&
            (!g_work_time || strncmp(stratum.job.job_id, g_work.job_id + 8, sizeof(g_work.job_id) - 8)))
        {
            pthread_mutex_lock(&g_work_lock);
            if (stratum_gen_work(&stratum, &g_work))
                g_work_time = time(NULL);
            if (stratum.job.clean)
            {
                static uint32_t last_block_height;
                if ((!opt_quiet || !firstwork_time) && stratum.job.height != last_block_height)
                {
                    last_block_height = stratum.job.height;
                    if (net_diff > 0.)
                        applog(LOG_BLUE, "%s block %d, diff %.3f", opt_algo,
                               stratum.job.height, net_diff);
                    else
                        applog(LOG_BLUE, "%s %s block %d", pool->short_url, opt_algo,
                               stratum.job.height);
                }
                restart_threads();
                if (check_dups || opt_showdiff)
                    hashlog_purge_old();
                stats_purge_old();
            }
            else if (opt_debug && !opt_quiet)
            {
                applog(LOG_BLUE, "%s asks job %d for block %d", pool->short_url,
                       strtoul(stratum.job.job_id, NULL, 16), stratum.job.height);
            }
            pthread_mutex_unlock(&g_work_lock);
        }

        if (switchn != pool_switch_count)
            goto pool_switched;

        if (!stratum_socket_full(&stratum, opt_timeout))
        {
            if (opt_debug)
                applog(LOG_WARNING, "Stratum connection timed out");
            s = NULL;
        }
        else
            s = stratum_recv_line(&stratum);

        if (switchn != pool_switch_count)
            goto pool_switched;

        if (!s)
        {
            stratum_disconnect(&stratum);
            if (!opt_quiet && !pool_on_hold)
                applog(LOG_WARNING, "Stratum connection interrupted");
            continue;
        }
        if (!stratum_handle_method(&stratum, s))
            handle_stratum_response(s);
        free(s);
    }

out:
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() died", __func__);

    return NULL;

pool_switched:
    stratum_disconnect(&(pools[pooln].stratum));
    if (stratum.url)
        free(stratum.url);
    stratum.url = NULL;
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() reinit...", __func__);
    goto wait_stratum_url;
}

static void show_version_and_exit(void)
{
    printf("%s v%s\n"
#ifdef WIN32
           "pthreads static %s\n"
#endif
           "%s\n",
           PACKAGE_NAME, PACKAGE_VERSION,
#ifdef WIN32
           PTW32_VERSION_STRING,
#endif
           curl_version());
    proper_exit(EXIT_CODE_OK);
}

static void show_usage_and_exit(int status)
{
    if (status)
        fprintf(stderr, "Try `" PROGRAM_NAME " --help' for more information.\n");
    else
        printf(usage);

    proper_exit(status);
}

void parse_arg(int key, char *arg)
{
    char *p = arg;
    int v, i;
    uint64_t ul;
    double d;

    switch (key)
    {
    case 'a':
        opt_algo = "ALGO_EQUIHASH";
        break;
    case 'b':
        p = strstr(arg, ":");
        if (p)
        {
            if (p - arg > 0)
            {
                free(opt_api_bind);
                opt_api_bind = strdup(arg);
                opt_api_bind[p - arg] = '\0';
            }
            opt_api_port = atoi(p + 1);
        }
        else if (arg && strstr(arg, "."))
        {
            free(opt_api_bind);
            opt_api_bind = strdup(arg);
        }
        else if (arg)
        {
            opt_api_port = atoi(arg);
        }
        break;
    case 1030:
        if (opt_api_allow)
            free(opt_api_allow);
        opt_api_allow = strdup("0/0");
        break;
    case 1031:
        if (!strcmp(arg, "0/0") && !strcmp(opt_api_bind, "127.0.0.1"))
            parse_arg('b', (char *)"0.0.0.0");
        if (opt_api_allow)
            free(opt_api_allow);
        opt_api_allow = strdup(arg);
        break;
    case 1032:
        if (opt_api_groups)
            free(opt_api_groups);
        opt_api_groups = strdup(arg);
        break;
    case 1033:
        opt_api_mcast = true;
        break;
    case 1034:
        free(opt_api_mcast_addr);
        opt_api_mcast_addr = strdup(arg);
    case 1035:
        free(opt_api_mcast_code);
        opt_api_mcast_code = strdup(arg);
        break;
    case 1036:
        free(opt_api_mcast_des);
        opt_api_mcast_des = strdup(arg);
        break;
    case 1037:
        v = atoi(arg);
        if (v < 1 || v > 65535)
            show_usage_and_exit(1);
        opt_api_mcast_port = v;
        break;
    case 'B':
        opt_background = true;
        break;
    case 'c':
    {
        json_error_t err;
        if (opt_config)
        {
            json_decref(opt_config);
            opt_config = NULL;
        }
        if (arg && strstr(arg, "://"))
        {
            opt_config = json_load_url(arg, &err);
        }
        else
        {
            opt_config = JSON_LOADF(arg, &err);
        }
        if (!json_is_object(opt_config))
        {
            applog(LOG_ERR, "JSON decode of %s failed", arg);
            proper_exit(EXIT_CODE_USAGE);
        }
        break;
    }

    case 'D':
        opt_debug = true;
        break;
    case 'N':
        v = atoi(arg);
        if (v < 1)
            opt_statsavg = INT_MAX;
        opt_statsavg = v;
        break;
    case 'n':
        proper_exit(EXIT_CODE_OK);
        break;
    case 'q':
        opt_quiet = true;
        break;
    case 'p':
        free(rpc_pass);
        rpc_pass = strdup(arg);
        pool_set_creds(cur_pooln);
        break;
    case 'P':
        opt_protocol = true;
        break;
    case 'r':
        v = atoi(arg);
        if (v < -1 || v > 9999)
            show_usage_and_exit(1);
        opt_retries = v;
        break;
    case 'R':
        v = atoi(arg);
        if (v < 1 || v > 9999)
            show_usage_and_exit(1);
        opt_fail_pause = v;
        break;
    case 's':
        v = atoi(arg);
        if (v < 1 || v > 9999)
            show_usage_and_exit(1);
        opt_scantime = v;
        break;
    case 'T':
        v = atoi(arg);
        if (v < 1 || v > 99999)
            show_usage_and_exit(1);
        opt_timeout = v;
        break;
    case 't':
        v = atoi(arg);
        if (v < 0 || v > 9999)
            show_usage_and_exit(1);
        opt_n_threads = v;
        break;
    case 1022:
        v = atoi(arg);
        if (v < 0 || v > 8192)
            show_usage_and_exit(1);
        opt_vote = (uint16_t)v;
        break;
    case 1023:
        opt_trust_pool = true;
        break;
    case 'u':
        free(rpc_user);
        rpc_user = strdup(arg);
        pool_set_creds(cur_pooln);
        break;
    case 'o':
        if (pools[cur_pooln].type != POOL_UNUSED)
        {
            cur_pooln = (cur_pooln + 1) % MAX_POOLS;
            num_pools = max(cur_pooln + 1, num_pools);
            if (opt_retries == -1)
                opt_retries = 1;
            if (opt_fail_pause == 30)
                opt_fail_pause = 5;
            if (opt_timeout == 300)
                opt_timeout = 60;
        }
        p = strstr(arg, "://");
        if (p)
        {
            if (strncasecmp(arg, "http://", 7) && strncasecmp(arg, "https://", 8) &&
                strncasecmp(arg, "stratum+tcp://", 14))
                show_usage_and_exit(1);
            free(rpc_url);
            rpc_url = strdup(arg);
            short_url = &rpc_url[(p - arg) + 3];
        }
        else
        {
            if (!strlen(arg) || *arg == '/')
                show_usage_and_exit(1);
            free(rpc_url);
            rpc_url = (char *)malloc(strlen(arg) + 8);
            snprintf(rpc_url, strlen(arg) + 8, "http://%s", arg);
            short_url = &rpc_url[7];
        }
        p = strrchr(rpc_url, '@');
        if (p)
        {
            char *sp, *ap;
            *p = '\0';
            ap = strstr(rpc_url, "://") + 3;
            sp = strchr(ap, ':');
            if (sp && sp < p)
            {
                free(rpc_user);
                rpc_user = (char *)calloc(sp - ap + 1, 1);
                strncpy(rpc_user, ap, sp - ap);
                free(rpc_pass);
                rpc_pass = strdup(sp + 1);
            }
            else
            {
                free(rpc_user);
                rpc_user = strdup(ap);
            }
            memmove(ap, p + 1, strlen(p + 1) + 1);
            short_url = ap;
        }
        have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
        pool_set_creds(cur_pooln);
        break;
    case 'O':
        p = strchr(arg, ':');
        if (!p)
            show_usage_and_exit(1);
        free(rpc_user);
        rpc_user = (char *)calloc(p - arg + 1, 1);
        strncpy(rpc_user, arg, p - arg);
        free(rpc_pass);
        rpc_pass = strdup(p + 1);
        pool_set_creds(cur_pooln);
        break;
    case 'x':
        if (!strncasecmp(arg, "socks4://", 9))
            opt_proxy_type = CURLPROXY_SOCKS4;
        else if (!strncasecmp(arg, "socks5://", 9))
            opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
        else if (!strncasecmp(arg, "socks4a://", 10))
            opt_proxy_type = CURLPROXY_SOCKS4A;
        else if (!strncasecmp(arg, "socks5h://", 10))
            opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
        else
            opt_proxy_type = CURLPROXY_HTTP;
        free(opt_proxy);
        opt_proxy = strdup(arg);
        pool_set_creds(cur_pooln);
        break;
    case 1001:
        free(opt_cert);
        opt_cert = strdup(arg);
        break;
    case 1002:
        use_colors = false;
        break;

    case 1074:
        opt_keep_clocks = true;
        break;

    case 1005:
        opt_benchmark = true;
        want_longpoll = false;
        want_stratum = false;
        have_stratum = false;
        break;
    case 1006:

        proper_exit(EXIT_CODE_OK);
        break;
    case 1003:
        want_longpoll = false;
        break;
    case 1007:
        want_stratum = false;
        opt_extranonce = false;
        break;
    case 1008:
        opt_time_limit = atoi(arg);
        break;
    case 1009:
        opt_shares_limit = atoi(arg);
        break;
    case 1011:
        allow_gbt = false;
        break;
    case 1012:
        opt_extranonce = false;
        break;
    case 1013:
        opt_showdiff = true;
        break;
    case 1014:
        opt_showdiff = false;
        break;
    case 1015:
        opt_submit_stale = true;
        break;
    case 'S':
    case 1018:
        applog(LOG_INFO, "Now logging to syslog...");
        use_syslog = true;
        if (arg && strlen(arg))
        {
            free(opt_syslog_pfx);
            opt_syslog_pfx = strdup(arg);
        }
        break;
    case 1019:
        opt_maxlograte = atoi(arg);
        break;
    case 1020:
        p = strstr(arg, "0x");
        ul = p ? strtoul(p, NULL, 16) : atol(arg);
        if (ul > (1UL << num_cpus) - 1)
            ul = -1L;
        opt_affinity = ul;
        break;
    case 1021:
        v = atoi(arg);
        if (v < 0 || v > 5)
            show_usage_and_exit(1);
        opt_priority = v;
        break;
    case 1025:
        opt_cudaschedule = atoi(arg);
        break;
    case 1060:
        d = atof(arg);
        opt_max_temp = d;
        break;
    case 1061:
        d = atof(arg);
        opt_max_diff = d;
        break;
    case 1062:
        d = atof(arg);
        p = strstr(arg, "K");
        if (p)
            d *= 1e3;
        p = strstr(arg, "M");
        if (p)
            d *= 1e6;
        p = strstr(arg, "G");
        if (p)
            d *= 1e9;
        opt_max_rate = d;
        break;
    case 1063:
        d = atof(arg);
        opt_resume_diff = d;
        break;
    case 1064:
        d = atof(arg);
        p = strstr(arg, "K");
        if (p)
            d *= 1e3;
        p = strstr(arg, "M");
        if (p)
            d *= 1e6;
        p = strstr(arg, "G");
        if (p)
            d *= 1e9;
        opt_resume_rate = d;
        break;
    case 1065:
        d = atof(arg);
        opt_resume_temp = d;
        break;
    case 'd':
    {
        int device_thr[MAX_GPUS] = {0};
        int ngpus = 1;
        char *pch = strtok(arg, ",");
        opt_n_threads = 0;
        while (pch != NULL && opt_n_threads < MAX_GPUS)
        {
            if (pch[0] >= '0' && pch[0] <= '9' && strlen(pch) <= 2)
            {
                if (atoi(pch) < ngpus)
                    device_map[opt_n_threads++] = atoi(pch);
                else
                {
                    applog(LOG_ERR, "Non-existant CUDA device #%d specified in -d option", atoi(pch));
                    proper_exit(EXIT_CODE_CUDA_NODEVICE);
                }
            }
            else
            {
                int device = 1;
                if (device >= 0 && device < ngpus)
                    device_map[opt_n_threads++] = device;
                else
                {
                    applog(LOG_ERR, "Non-existant CUDA device '%s' specified in -d option", pch);
                    proper_exit(EXIT_CODE_CUDA_NODEVICE);
                }
            }
            pch = strtok(NULL, ",");
        }
        for (int n = 0; n < opt_n_threads; n++)
        {
            int device = device_map[n];
            device_thr[device]++;
        }
        for (int n = 0; n < ngpus; n++)
        {
            gpu_threads = max(gpu_threads, device_thr[n]);
        }
    }
    break;

    case 'f':
        d = atof(arg);
        if (d <= 0.)
            show_usage_and_exit(1);
        opt_difficulty = d;
        break;
    case 'm':
        d = atof(arg);
        if (d <= 0.)
            show_usage_and_exit(1);
        opt_difficulty = 1.0 / d;
        break;

    case 1100:
        pool_set_attr(cur_pooln, "name", arg);
        break;
    case 1101:
        pool_set_attr(cur_pooln, "algo", arg);
        break;
    case 1102:
        pool_set_attr(cur_pooln, "scantime", arg);
        break;
    case 1108:
        pool_set_attr(cur_pooln, "time-limit", arg);
        break;
    case 1109:
        pool_set_attr(cur_pooln, "shares-limit", arg);
        break;
    case 1161:
        pool_set_attr(cur_pooln, "max-diff", arg);
        break;
    case 1162:
        pool_set_attr(cur_pooln, "max-rate", arg);
        break;
    case 1199:
        pool_set_attr(cur_pooln, "disabled", arg);
        break;

    case 'V':
        show_version_and_exit();
    case 'h':
        show_usage_and_exit(0);
    default:
        show_usage_and_exit(1);
    }

    if (use_syslog)
        use_colors = false;
}

void parse_config(json_t *json_obj)
{
    int i;
    json_t *val;

    if (!json_is_object(json_obj))
        return;

    for (i = 0; i < ARRAY_SIZE(options); i++)
    {

        if (!options[i].name)
            break;

        if (!strcasecmp(options[i].name, "config"))
            continue;

        val = json_object_get(json_obj, options[i].name);
        if (!val)
            continue;

        if (options[i].has_arg && json_is_string(val))
        {
            char *s = strdup(json_string_value(val));
            if (!s)
                continue;
            parse_arg(options[i].val, s);
            free(s);
        }
        else if (options[i].has_arg && json_is_integer(val))
        {
            char buf[16];
            snprintf(buf, sizeof(buf), "%d", (int)json_integer_value(val));
            parse_arg(options[i].val, buf);
        }
        else if (options[i].has_arg && json_is_real(val))
        {
            char buf[16];
            snprintf(buf, sizeof(buf), "%f", json_real_value(val));
            parse_arg(options[i].val, buf);
        }
        else if (!options[i].has_arg)
        {
            if (json_is_true(val))
                parse_arg(options[i].val, (char *)"");
        }
        else
            applog(LOG_ERR, "JSON option %s invalid",
                   options[i].name);
    }

    val = json_object_get(json_obj, "pools");
    if (val && json_typeof(val) == JSON_ARRAY)
    {
        parse_pool_array(val);
    }
}

static void parse_cmdline(int argc, char *argv[])
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

static void parse_single_opt(int opt, int argc, char *argv[])
{
    int key, prev = optind;
    while (1)
    {
#if HAVE_GETOPT_LONG
        key = getopt_long(argc, argv, short_options, options, NULL);
#else
        key = getopt(argc, argv, short_options);
#endif
        if (key < 0)
            break;
        if (key == opt)
            parse_arg(key, optarg);
    }

    optind = prev;
}

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

int main(int argc, char *argv[])
{
    struct thr_info *thr;
    long flags;
    int i;

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
