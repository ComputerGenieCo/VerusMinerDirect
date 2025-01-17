#ifndef MINER_H
#define MINER_H

// System includes
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/time.h>
#include <pthread.h>

// Platform-specific system includes
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

// Third party includes
#include <jansson.h>
#include <curl/curl.h>

// Project includes
#include "constants.h"
#include "config.h"
#include "stratum.h"
#include "miner-config.h"
#include "compat.h"
#include "types.h"
#include "workio.h"
#include "util.h" // Add this include
#include "threading.h"  // Add this include

// Type definitions
typedef unsigned char uchar;

// Enums and structs
#ifndef HAVE_GETOPT_LONG
struct option {
    const char *name;
    int has_arg;
    int *flag;
    int val;
};
#endif

// Preprocessor definitions
#define USER_AGENT PACKAGE_NAME "/" PACKAGE_VERSION

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads((str), 0, (err_ptr))
#define JSON_LOADF(str, err_ptr) json_load_file((str), 0, (err_ptr))
#else
#define JSON_LOADS(str, err_ptr) json_loads((str), (err_ptr))
#define JSON_LOADF(str, err_ptr) json_load_file((str), (err_ptr))
#endif

// Platform-specific type handling
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

// Alignment and optimization macros
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

// Inline utility functions
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

// Remove the swab32 implementation since it's now in util.h

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

// Byte order conversion functions
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

// External variable declarations
extern int active_gpus;
extern uint64_t global_hashrate;
extern uint64_t net_hashrate;
extern double net_diff;
extern double stratum_diff;
extern int cryptonight_fork;

extern int longpoll_thr_id;
extern int stratum_thr_id;
extern int api_thr_id;
extern volatile bool abort_flag;
extern struct work_restart *work_restart;

extern char *device_name[MAX_GPUS];
extern short device_map[MAX_GPUS];
extern short device_mpcount[MAX_GPUS];
extern long device_sm[MAX_GPUS];
extern uint32_t device_plimit[MAX_GPUS];
extern uint32_t gpus_intensity[MAX_GPUS];

extern struct pool_infos pools[MAX_POOLS];
extern int num_pools;
extern volatile int cur_pooln;

extern int app_exit_code;

#ifdef __cplusplus
extern "C" {
#endif

// CUDA function declarations
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

// Logging function declarations 
void applog(int prio, const char *fmt, ...);            
void gpulog(int prio, int thr_id, const char *fmt, ...);
void cuda_log_lasterror(int thr_id, const char *func, int line);
void cuda_clear_lasterror();
#define CUDA_LOG_ERROR() cuda_log_lasterror(thr_id, __func__, __LINE__)

// Work management function declarations
bool get_work(struct thr_info *thr, struct work *work);
bool submit_work(struct thr_info *thr, const struct work *work_in);
void workio_abort(void);
void *workio_thread(void *userdata);
int scan_for_valid_hashes(int thr_id, struct work *work, uint32_t max_nonce, unsigned long *hashes_done);

// Utility function declarations
extern int options_count();
extern void proper_exit(int reason);
extern void restart_threads();
extern void format_hashrate(double hashrate, char *output);
extern void format_hashrate_unit(double hashrate, char *output, const char *unit);
extern void get_currentalgo(char *buf, int sz);
extern void *aligned_calloc(int size);
extern void aligned_free(void *ptr);

extern bool hex2bin(void *output, const char *hexstr, size_t len);
extern void cbin2hex(char *out, const char *in, size_t len);
extern char *bin2hex(const uchar *in, size_t len);
extern int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);

extern void get_defconfig_path(char *out, size_t bufsize, char *argv0);

// Mining algorithm function declarations
extern double verus_network_diff(struct work *work);
extern void work_set_target_ratio(struct work *work, uint32_t *hash);
extern bool fulltest(const uint32_t *hash, const uint32_t *target);
extern void diff_to_target(uint32_t *target, double diff);
extern void work_set_target(struct work *work, double diff);
extern double target_to_diff(uint32_t *target);

// Pool management function declarations
extern void pool_init_defaults(void);
extern void pool_set_creds(int pooln);
extern void pool_set_attr(int pooln, const char *key, char *arg);
extern bool pool_switch(int thr_id, int pooln);
extern bool pool_switch_url(char *params);
extern bool pool_switch_next(int thr_id);
extern int pool_get_first_valid(int startfrom);
extern void pool_dump_infos(void);

// API function declarations
void *api_thread(void *userdata);
void api_set_throughput(int thr_id, uint32_t throughput);
void gpu_increment_reject(int thr_id);

// Hash logging function declarations
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

// Stats function declarations
void stats_remember_speed(int thr_id, uint32_t hashcount, double hashrate, uint8_t found, uint32_t height);
double stats_get_speed(int thr_id, double def_speed);
double stats_get_gpu_speed(int gpu_id);
int stats_get_history(int thr_id, struct stats_data *data, int max_records);
void stats_purge_old(void);
void stats_purge_all(void);
void stats_getmeminfo(uint64_t *mem, uint32_t *records);

// Remove these declarations since they're now in threading.h:
/* extern struct thread_q *tq_new(void);
extern void tq_free(struct thread_q *tq);
extern bool tq_push(struct thread_q *tq, void *data);
extern void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
extern void tq_freeze(struct thread_q *tq);
extern void tq_thaw(struct thread_q *tq);
extern void initialize_mining_threads(int num_threads); */

size_t time2str(char *buf, time_t timer);
char *atime2str(time_t timer);

void print_hash_tests(void);

bool get_work(struct thr_info *thr, struct work *work);
bool submit_work(struct thr_info *thr, const struct work *work_in); 
void workio_abort(void);
void *workio_thread(void *userdata);
void initialize_mining_threads(int num_threads);

double bn_hash_target_ratio(uint32_t *hash, uint32_t *target);
void bn_store_hash_target_ratio(uint32_t *hash, uint32_t *target, struct work *work, int nonce);
void bn_set_target_ratio(struct work *work, uint32_t *hash, int nonce);

#ifdef __cplusplus  
}
#endif

extern struct thr_info *thr_info;

#endif /* MINER_H */
