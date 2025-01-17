#ifndef CONFIG_H
#define CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

// System/library includes
#include <jansson.h>
#include <getopt.h>
#include <cstdint>

// Global configuration variables
// Algorithm/mining related
extern const char* opt_algo;
extern int opt_n_threads;
extern int opt_scantime;
extern int opt_retries;
extern int opt_fail_pause;
extern int opt_timeout;
extern int opt_time_limit;
extern int opt_shares_limit;
extern int opt_priority;
extern double opt_difficulty;
extern int opt_cudaschedule;
extern int opt_nfactor;
extern int gpu_threads;

// Control flags
extern bool opt_debug;
extern bool opt_protocol;
extern bool opt_benchmark;
extern bool opt_redirect;
extern bool opt_background;
extern bool opt_quiet;
extern bool opt_extranonce;
extern bool opt_submit_stale;
extern bool opt_keep_clocks;
extern bool opt_showdiff;
extern bool opt_autotune;
extern bool opt_debug_threads;
extern bool opt_debug_diff;

// Pool/network related
extern bool want_longpoll;
extern bool have_longpoll;
extern bool want_stratum;
extern bool have_stratum;
extern bool allow_gbt;
extern bool allow_mininginfo;
extern bool check_dups;
extern bool check_stratum_jobs;
extern bool submit_old;
extern time_t firstwork_time;

// System/hardware related
extern int num_cpus;
extern long opt_affinity;
extern bool use_syslog;
extern bool use_colors;

// Performance/monitoring
extern double opt_max_temp;
extern double opt_max_diff;
extern double opt_max_rate;
extern double opt_resume_diff;
extern double opt_resume_rate;
extern double opt_resume_temp;
extern int opt_statsavg;
extern int opt_maxlograte;

// API related
extern uint16_t opt_vote;
extern int opt_api_port;
extern char *opt_api_allow;
extern char *opt_api_bind;
extern char *opt_api_groups;
extern bool opt_api_mcast;
extern char *opt_api_mcast_addr;
extern char *opt_api_mcast_code;
extern char *opt_api_mcast_des;
extern int opt_api_mcast_port;

// Network security/authentication
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool opt_trust_pool;
extern bool opt_stratum_stats;
extern char *rpc_user;
extern char *rpc_pass;
extern char *rpc_url;
extern char *short_url;

// Miscellaneous
extern json_t *opt_config;
extern int use_pok;
extern char *opt_syslog_pfx;

// Command line options
extern struct option options[];
extern const char short_options[];

// Function declarations
void init_config_defaults(void);
void free_config(void);
void parse_arg(int key, char *arg);
void parse_config(json_t *config);
void parse_cmdline(int argc, char *argv[]);
void parse_single_opt(int opt, int argc, char *argv[]);
void show_usage_and_exit(int status);
void show_version_and_exit(void);
void parse_command_line_arguments(int argc, char *argv[]);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_H */
