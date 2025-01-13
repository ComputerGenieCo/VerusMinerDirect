/**
 * @file main.h
 * @brief Main header file for the VerusMiner cryptocurrency mining application
 *
 * This file contains core type definitions, function declarations, and constants
 * used throughout the VerusMiner application. It handles GPU mining operations,
 * network communication, and mining pool interactions.
 */

#ifndef MINER_H
#define MINER_H

#include "config.h"

// Core includes
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/time.h>
#include <pthread.h>
#include <jansson.h>
#include <curl/curl.h>
#include "miner-config.h"
#include "compat.h"
#include "types.h"
#include "constants.h"
#include "workio.h"

// Platform-specific includes
#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#endif

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#endif

#ifdef _MSC_VER
#include <malloc.h>
#undef HAVE_ALLOCA_H
#undef HAVE_SYSLOG_H
#endif

/**
 * @brief Type definition for unsigned char used throughout the application
 */
typedef unsigned char uchar;

// Platform-specific type definitions and enums
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#else
#ifndef LOG_ERR
enum
{
    LOG_ERR,
    LOG_WARNING,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG,
};
#endif
#endif

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option
{
    const char *name;
    int has_arg;
    int *flag;
    int val;
};
#endif

// Constants and compiler macros
#define USER_AGENT PACKAGE_NAME "/" PACKAGE_VERSION

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))
#define JSON_LOADF(str, err_ptr) json_load_file((str), 0, (err_ptr))
#else
#define JSON_LOADS(str, err_ptr) json_loads((str), (err_ptr))
#define JSON_LOADF(str, err_ptr) json_load_file((str), (err_ptr))
#endif

#ifdef __INTELLISENSE__
	typedef __int64 int64_t;
	typedef unsigned __int64 uint64_t;
	typedef __int32 int32_t;
	typedef unsigned __int32 uint32_t;
	typedef __int16 int16_t;
	typedef unsigned __int16 uint16_t;
	typedef __int16 int8_t;
	typedef unsigned __int16 uint8_t;

	typedef unsigned __int32 time_t;
	typedef char *va_list;
#endif

#if defined(__CUDA_ARCH__) && __CUDA_ARCH__ > 0
#undef _ALIGN
#define _ALIGN(x) __align__(x)
#endif

#undef unlikely
#undef likely
#if defined(__GNUC__) && (__GNUC__ > 2) && defined(__OPTIMIZE__)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

// Replace macro definitions with template functions
#ifndef max
template<typename T, typename U> 
static inline auto max(T a, U b) -> decltype(a > b ? a : b) { 
    return ((a) > (b) ? (a) : (b));
}
#endif

#ifndef min  
template<typename T, typename U>
static inline auto min(T a, U b) -> decltype(a < b ? a : b) { 
    return ((a) < (b) ? (a) : (b));
}
#endif

#ifndef UINT32_MAX
#define UINT32_MAX UINT_MAX
#endif

static inline bool is_windows(void)
{
#ifdef WIN32
	return 1;
#else
	return 0;
#endif
}

static inline bool is_x64(void)
{
#if defined(__x86_64__) || defined(_WIN64) || defined(__aarch64__)
	return 1;
#elif defined(__amd64__) || defined(__amd64) || defined(_M_X64) || defined(_M_IA64)
	return 1;
#else
	return 0;
#endif
}

#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
#define bswap_64(x) (((uint64_t)bswap_32((uint32_t)((x) & 0xffffffffu)) << 32) | (uint64_t)bswap_32((uint32_t)((x) >> 32)))
#endif

static inline uint32_t swab32(uint32_t v)
{
#ifdef WANT_BUILTIN_BSWAP
	return __builtin_bswap32(v);
#else
	return bswap_32(v);
#endif
}

static inline uint64_t swab64(uint64_t v)
{
#ifdef WANT_BUILTIN_BSWAP
	return __builtin_bswap64(v);
#else
	return bswap_64(v);
#endif
}

static inline void swab256(void *dest_p, const void *src_p)
{
	uint32_t *dest = (uint32_t *)dest_p;
	const uint32_t *src = (const uint32_t *)src_p;

	dest[0] = swab32(src[7]);
	dest[1] = swab32(src[6]);
	dest[2] = swab32(src[5]);
	dest[3] = swab32(src[4]);
	dest[4] = swab32(src[3]);
	dest[5] = swab32(src[2]);
	dest[6] = swab32(src[1]);
	dest[7] = swab32(src[0]);
}

#if !HAVE_DECL_BE32DEC
static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
			((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
			((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif

#if !HAVE_DECL_BE32ENC
static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE32ENC
static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}
#endif

#if defined(__FreeBSD__)
#define HAVE_DECL_BE16DEC 1
#define HAVE_DECL_LE16DEC 1
#define HAVE_DECL_BE16ENC 1
#define HAVE_DECL_LE16ENC 1
#endif

#if !HAVE_DECL_BE16DEC
static inline uint16_t be16dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint16_t)(p[1]) + ((uint16_t)(p[0]) << 8));
}
#endif

#if !HAVE_DECL_BE16ENC
static inline void be16enc(void *pp, uint16_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[1] = x & 0xff;
	p[0] = (x >> 8) & 0xff;
}
#endif

#if !HAVE_DECL_LE16DEC
static inline uint16_t le16dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint16_t)(p[0]) + ((uint16_t)(p[1]) << 8));
}
#endif

#if !HAVE_DECL_LE16ENC
static inline void le16enc(void *pp, uint16_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
}
#endif

/**
 * @brief Global configuration variables controlling mining behavior
 */
// Global variable declarations

// Remove these duplicate declarations since they're in config.h
// extern bool opt_benchmark;
// extern bool opt_quiet;
// extern bool opt_protocol; 
// extern bool opt_showdiff;
// extern int opt_n_threads;
// extern int opt_timeout;
// extern bool want_longpoll;
// extern bool have_longpoll;
// extern bool want_stratum;
// extern bool have_stratum;
// extern bool opt_stratum_stats;
// extern char *opt_cert;
// extern char *opt_proxy;
// extern long opt_proxy_type;
// extern bool opt_trust_pool;
// extern uint16_t opt_vote;
// extern int opt_fail_pause;
// extern int opt_retries;

// Keep non-duplicated declarations
extern int active_gpus;
extern int use_pok;
extern struct thr_info *thr_info;
extern int longpoll_thr_id;
extern int stratum_thr_id;
extern int api_thr_id;
extern volatile bool abort_flag;
extern struct work_restart *work_restart;

extern uint64_t global_hashrate;
extern uint64_t net_hashrate;
extern double net_diff;
extern double stratum_diff;

extern char *device_name[MAX_GPUS];
extern short device_map[MAX_GPUS];
extern short device_mpcount[MAX_GPUS];
extern long device_sm[MAX_GPUS];
extern uint32_t device_plimit[MAX_GPUS];
extern uint32_t gpus_intensity[MAX_GPUS];
extern int opt_cudaschedule;

extern int cryptonight_fork;

extern struct pool_infos pools[MAX_POOLS];
extern int num_pools;
extern volatile int cur_pooln;

extern int cuda_num_devices();
void cuda_devicenames();
void cuda_reset_device(int thr_id, bool *init);
void cuda_shutdown();
int cuda_finddevice(char *name);
int cuda_version();
void cuda_print_devices();
int cuda_gpu_info(struct cgpu_info *gpu);
int cuda_available_memory(int thr_id);

uint32_t cuda_default_throughput(int thr_id, uint32_t defcount);
#define device_intensity(t, f, d) cuda_default_throughput(t, d)
double throughput2intensity(uint32_t throughput);

void cuda_log_lasterror(int thr_id, const char *func, int line);
void cuda_clear_lasterror();
#define CUDA_LOG_ERROR() cuda_log_lasterror(thr_id, __func__, __LINE__)

/**
 * @brief Core mining functions 
 */
extern int options_count();                    ///< Get count of command line options
extern void proper_exit(int reason);           ///< Clean program termination
extern void restart_threads();                 ///< Restart all mining threads

/**
 * @brief Utility functions for mining operations
 */
extern void format_hashrate(double hashrate, char *output);     ///< Format hashrate for display
extern void format_hashrate_unit(double hashrate, char *output, const char *unit); ///< Format hashrate with units

#ifdef __cplusplus
extern "C" {
#endif

// Move these logging functions inside extern "C" block
void applog(int prio, const char *fmt, ...);            ///< Application logging
void gpulog(int prio, int thr_id, const char *fmt, ...);///< GPU-specific logging

// Move work-related functions inside extern "C" block
bool get_work(struct thr_info *thr, struct work *work);
bool submit_work(struct thr_info *thr, const struct work *work_in);
void workio_abort(void);
void *workio_thread(void *userdata);

// Move scan_for_valid_hashes into extern "C" block
int scan_for_valid_hashes(int thr_id, struct work *work, uint32_t max_nonce, unsigned long *hashes_done);

#ifdef __cplusplus
}
#endif

extern void get_currentalgo(char *buf, int sz);
extern void *aligned_calloc(int size);
extern void aligned_free(void *ptr);

/**
 * @brief Binary/hex conversion utilities
 */
extern bool hex2bin(void *output, const char *hexstr, size_t len);     ///< Convert hex string to binary
extern void cbin2hex(char *out, const char *in, size_t len);          ///< Convert binary to hex string with fixed buffer
extern char *bin2hex(const uchar *in, size_t len);                    ///< Convert binary to hex string with allocation

/**
 * @brief Time-related utility functions
 */
extern int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y); ///< Calculate time difference

/**
 * @brief Configuration file handling
 */
extern void get_defconfig_path(char *out, size_t bufsize, char *argv0); ///< Get default config file path

/**
 * @brief Mining algorithm implementations
 */
extern double verus_network_diff(struct work *work);           ///< Calculate network difficulty for Verus
extern void work_set_target_ratio(struct work *work, uint32_t *hash); ///< Set work target ratio
extern bool fulltest(const uint32_t *hash, const uint32_t *target);   ///< Test if hash meets target
extern void diff_to_target(uint32_t *target, double diff);
extern void work_set_target(struct work *work, double diff);
extern double target_to_diff(uint32_t *target);

#ifdef __cplusplus
extern "C" {
#endif

double bn_hash_target_ratio(uint32_t *hash, uint32_t *target);
void bn_store_hash_target_ratio(uint32_t *hash, uint32_t *target, struct work *work, int nonce);
void bn_set_target_ratio(struct work *work, uint32_t *hash, int nonce);

#ifdef __cplusplus  
}
#endif

/**
 * @brief Network and stratum protocol functions
 */
extern void pool_init_defaults(void);                         ///< Initialize mining pool defaults
extern void pool_set_creds(int pooln);                       ///< Set pool credentials
extern void pool_set_attr(int pooln, const char *key, char *arg); ///< Set pool attributes
extern bool pool_switch(int thr_id, int pooln);
extern bool pool_switch_url(char *params);
extern bool pool_switch_next(int thr_id);
extern int pool_get_first_valid(int startfrom);
extern void pool_dump_infos(void);

// ...existing code for other function declarations...

void *api_thread(void *userdata);
void api_set_throughput(int thr_id, uint32_t throughput);
void gpu_increment_reject(int thr_id);

void hashlog_remember_submit(struct work *work, uint32_t nonce);
void hashlog_remember_scan_range(struct work *work);
double hashlog_get_sharediff(char *jobid, int idnonce, double defvalue);
uint32_t hashlog_already_submittted(char *jobid, uint32_t nounce);
uint32_t hashlog_get_last_sent(char *jobid);
uint64_t hashlog_get_scan_range(char *jobid);
int hashlog_get_history(struct hashlog_data *data, int max_records);
void hashlog_purge_old(void);
void hashlog_purge_job(char *jobid);
void hashlog_purge_all(void);
void hashlog_dump_job(char *jobid);
void hashlog_getmeminfo(uint64_t *mem, uint32_t *records);

void stats_remember_speed(int thr_id, uint32_t hashcount, double hashrate, uint8_t found, uint32_t height);
double stats_get_speed(int thr_id, double def_speed);
double stats_get_gpu_speed(int gpu_id);
int stats_get_history(int thr_id, struct stats_data *data, int max_records);
void stats_purge_old(void);
void stats_purge_all(void);
void stats_getmeminfo(uint64_t *mem, uint32_t *records);

struct thread_q;

extern struct thread_q *tq_new(void);
extern void tq_free(struct thread_q *tq);
extern bool tq_push(struct thread_q *tq, void *data);
extern void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
extern void tq_freeze(struct thread_q *tq);
extern void tq_thaw(struct thread_q *tq);

void parse_arg(int key, char *arg);

size_t time2str(char *buf, time_t timer);
char *atime2str(time_t timer);

// Remove logging constants and functions that were moved to logging.h
// Remove LOG_RAW and LOG_BLUE defines
// Remove applog_hex, applog_hash, applog_hash64, applog_compare_hash declarations

void print_hash_tests(void);

json_t *json_load_url(char *cfg_url, json_error_t *err);
json_t *json_rpc_call_pool(CURL *curl, struct pool_infos *pool,
						   const char *req, bool lp_scan, bool lp, int *err);
json_t *json_rpc_longpoll(CURL *curl, char *lp_url, struct pool_infos *pool,
						  const char *req, int *err);
bool parse_pool_array(json_t *obj);

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);
void stratum_free_job(struct stratum_ctx *sctx);

bool equi_stratum_notify(struct stratum_ctx *sctx, json_t *params);
bool equi_stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params);
bool equi_stratum_set_target(struct stratum_ctx *sctx, json_t *params);
bool equi_stratum_submit(struct pool_infos *pool, struct work *work);
void equi_work_set_target(struct work* work, double diff);

// Work I/O related functions
bool get_work(struct thr_info *thr, struct work *work);
bool submit_work(struct thr_info *thr, const struct work *work_in); 
void workio_abort(void);
void *workio_thread(void *userdata);
void initialize_mining_threads(int num_threads);

#ifdef __cplusplus
#endif

#endif /* MINER_H */
