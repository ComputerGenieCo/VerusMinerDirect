#ifndef __UTIL_H__
#define __UTIL_H__

#include <curl/curl.h>
#include <jansson.h>
#include <cstdint>  // Include cstdint for uint32_t

// Forward declarations of types
struct pool_infos;
struct stratum_ctx;
struct work;
struct thread_q;

#ifdef __cplusplus
extern "C" {
#endif

#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
#endif

static inline uint32_t swab32(uint32_t v)
{
#ifdef WANT_BUILTIN_BSWAP
    return __builtin_bswap32(v);
#else
    return bswap_32(v);
#endif
}

// Function declarations
json_t *json_rpc_call_pool(CURL *curl, struct pool_infos *pool, const char *rpc_req, 
                          bool lp_scan, bool lock, int *err);
json_t *json_rpc_longpoll(CURL *curl, char *lp_url, struct pool_infos *pool, const char *req, int *curl_err);
json_t *json_load_url(char *cfg_url, json_error_t *err);
void *aligned_calloc(int size);
void aligned_free(void *ptr);
void cbin2hex(char *out, const char *in, size_t len);
char *bin2hex(const unsigned char *in, size_t len);
bool hex2bin(void *output, const char *hexstr, size_t len);
int timeval_subtract(struct timeval *result, struct timeval *x, struct timeval *y);
bool fulltest(const uint32_t *hash, const uint32_t *target);
void diff_to_target(uint32_t *target, double diff);
void work_set_target(struct work* work, double diff);
double target_to_diff(uint32_t* target);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
void stratum_free_job(struct stratum_ctx *sctx);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_notify(struct stratum_ctx *sctx, json_t *params);
bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params);
bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params);
bool stratum_pong(struct stratum_ctx *sctx, json_t *id);
bool stratum_get_algo(struct stratum_ctx *sctx, json_t *id, json_t *params);
bool stratum_get_stats(struct stratum_ctx *sctx, json_t *id, json_t *params);
bool stratum_get_version(struct stratum_ctx *sctx, json_t *id, json_t *params);
bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params);
bool stratum_unknown_method(struct stratum_ctx *sctx, json_t *id);
void tq_freeze(struct thread_q *tq);
void tq_thaw(struct thread_q *tq);
bool tq_push(struct thread_q *tq, void *data);
void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
void get_defconfig_path(char *out, size_t bufsize, char *argv0);
void format_hashrate_unit(double hashrate, char *output, const char *unit);

#ifdef __cplusplus
}
#endif

#endif // __UTIL_H__
