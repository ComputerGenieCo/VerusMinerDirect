#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <getopt.h>
#include <jansson.h>
#include <curl/curl.h>

#include "main.h"
#include "config.h"
#include "logging.h"

// Define all the extern variables declared in config.h
const char* opt_algo = NULL;
bool opt_debug = false;
bool opt_protocol = false;
bool opt_benchmark = false;
bool opt_redirect = false;
bool opt_background = false;
bool opt_quiet = false;
bool opt_extranonce = true;
bool want_longpoll = true;
bool have_longpoll = false;
bool want_stratum = true;
bool have_stratum = false;
bool allow_gbt = true;
bool use_syslog = false;
bool use_colors = true;
bool opt_submit_stale = false;
bool opt_keep_clocks = false;
bool opt_showdiff = false;
int opt_n_threads = 0;
int opt_scantime = 10;
int opt_retries = -1;
int opt_fail_pause = 30;
int opt_timeout = 300;
int opt_time_limit = 0;
int opt_shares_limit = 0;
int num_cpus = 1;
long opt_affinity = -1;
int opt_priority = 0;
double opt_difficulty = 1.0;
double opt_max_temp = 0.0;
double opt_max_diff = 0.0;
double opt_max_rate = 0.0;
double opt_resume_diff = 0.0;
double opt_resume_rate = 0.0;
double opt_resume_temp = 0.0;
int opt_statsavg = 30;
int opt_maxlograte = 3;
uint16_t opt_vote = 9999;
int opt_api_port = 4068;
int use_pok = 0;
// API related variables
char *opt_api_allow = NULL;
char *opt_api_bind = NULL;
char *opt_api_groups = NULL;
bool opt_api_mcast = false;
char *opt_api_mcast_addr = NULL;
char *opt_api_mcast_code = NULL;
char *opt_api_mcast_des = NULL;
int opt_api_mcast_port = 4068;

// RPC related variables
char *rpc_user = NULL;
char *rpc_pass = NULL;
char *rpc_url = NULL;
char *short_url = NULL;

// JSON config
json_t *opt_config = NULL;

// New variables
char *opt_cert = NULL;
char *opt_proxy = NULL;
long opt_proxy_type = CURLPROXY_HTTP;
bool opt_trust_pool = false;
bool opt_stratum_stats = false;

// Initialize debug option variables
bool opt_debug_threads = false;
bool opt_debug_diff = false;

char *opt_syslog_pfx = nullptr;

const char usage[] = "\
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

// Keep array declaration as is
const char short_options[] =
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

void show_usage_and_exit(int status)
{
    if (status)
        fprintf(stderr, "Try `" PROGRAM_NAME " --help' for more information.\n");
    else
        printf(usage);

    proper_exit(status);
}

void show_version_and_exit(void)
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

void parse_cmdline(int argc, char *argv[])
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

void parse_single_opt(int opt, int argc, char *argv[])
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

// Add global initialization function
void init_config_defaults() {
    // Initialize strings to NULL or defaults
    rpc_user = NULL;
    rpc_pass = NULL; 
    rpc_url = NULL;
    short_url = NULL;
    opt_api_bind = strdup("127.0.0.1"); // Default API bind address
    opt_api_allow = NULL;
    opt_api_groups = NULL;
    opt_api_mcast_addr = NULL;
    opt_api_mcast_code = NULL;
    opt_api_mcast_des = NULL;
    opt_cert = NULL;
    opt_proxy = NULL;
    opt_syslog_pfx = NULL;

    // Initialize other defaults
    opt_algo = "verus";
    opt_n_threads = 0; // Will be set based on GPU count
    opt_scantime = 10;
    opt_retries = -1;
    opt_fail_pause = 30;
    opt_timeout = 300;
    opt_api_port = 4068;
    opt_proxy_type = CURLPROXY_HTTP;
    
    // Initialize pools array
    memset(pools, 0, sizeof(pools));
    num_pools = 0;
    cur_pooln = 0;

    // Set initial boolean flags
    want_longpoll = true;
    want_stratum = true;
    have_stratum = false;
    have_longpoll = false;
    opt_extranonce = true;
    use_colors = true;
    opt_trust_pool = false;
}

// Add cleanup function
void free_config() {
    // Free allocated strings
    free(rpc_user);
    free(rpc_pass);
    free(rpc_url);
    free(opt_api_bind);
    free(opt_api_allow);
    free(opt_api_groups);
    free(opt_api_mcast_addr);
    free(opt_api_mcast_code); 
    free(opt_api_mcast_des);
    free(opt_cert);
    free(opt_proxy);
    free(opt_syslog_pfx);

    // Free JSON config if exists
    if (opt_config) {
        json_decref(opt_config);
        opt_config = NULL;
    }

    // Clean up pools
    for (int i = 0; i < MAX_POOLS; i++) {
        if (pools[i].url) free(pools[i].url);
        if (pools[i].user) free(pools[i].user);
        if (pools[i].pass) free(pools[i].pass);
        // ...free other pool members...
    }
}
