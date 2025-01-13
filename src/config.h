#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <getopt.h>
#include <cstdint>
// Configuration variables
extern const char* opt_algo;
extern bool opt_debug;
extern bool opt_protocol;
extern bool opt_benchmark;
extern bool opt_redirect;
extern bool opt_background;
extern bool opt_quiet;
extern bool opt_extranonce;
extern bool want_longpoll;
extern bool have_longpoll;
extern bool want_stratum;
extern bool have_stratum;
extern bool allow_gbt;
extern bool use_syslog;
extern bool use_colors;
extern bool opt_submit_stale;
extern bool opt_keep_clocks;
extern bool opt_showdiff;
extern int opt_n_threads;
extern int opt_scantime;
extern int opt_retries;
extern int opt_fail_pause;
extern int opt_timeout;
extern int opt_time_limit;
extern int opt_shares_limit;
extern int num_cpus;
extern long opt_affinity;
extern int opt_priority;
extern double opt_difficulty;
extern double opt_max_temp;
extern double opt_max_diff;
extern double opt_max_rate;
extern double opt_resume_diff;
extern double opt_resume_rate;
extern double opt_resume_temp;
extern int opt_statsavg;
extern int opt_maxlograte;
extern uint16_t opt_vote;
extern int opt_api_port;
extern int gpu_threads;
// Additional config variables needed for networking
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool opt_trust_pool;
extern bool opt_stratum_stats;

// Additional config variables needed for debug
extern bool opt_debug_threads;
extern bool opt_debug_diff;

// API related variables
extern char *opt_api_allow;
extern char *opt_api_bind;
extern char *opt_api_groups;
extern bool opt_api_mcast;
extern char *opt_api_mcast_addr;
extern char *opt_api_mcast_code;
extern char *opt_api_mcast_des;
extern int opt_api_mcast_port;

// RPC related variables
extern char *rpc_user;
extern char *rpc_pass;
extern char *rpc_url;
extern char *short_url;

// JSON config
extern json_t *opt_config;

// Function declarations
void parse_arg(int key, char *arg);
void parse_config(json_t *config);
void parse_cmdline(int argc, char *argv[]);
void parse_single_opt(int opt, int argc, char *argv[]);
void show_usage_and_exit(int status);
void show_version_and_exit(void);

// Add these function declarations
#ifdef __cplusplus
extern "C" {
#endif

void init_config_defaults(void);
void free_config(void);

#ifdef __cplusplus
}
#endif

// Command line options
extern struct option options[];
extern const char short_options[]; // Change from pointer to array declaration

extern char *opt_syslog_pfx;

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_H */
