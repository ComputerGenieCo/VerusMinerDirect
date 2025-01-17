#ifndef STRATUM_H
#define STRATUM_H

#define EQNONCE_OFFSET 30

#include <jansson.h>
#include <curl/curl.h>
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// External variables
extern bool stratum_need_reset;

// Core stratum interface
void *stratum_thread(void *userdata);
bool handle_stratum_response(char *buf);
bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work);

// Connection management
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);

// Protocol implementation
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);
void stratum_free_job(struct stratum_ctx *sctx);

// JSON-RPC utilities
json_t *json_rpc_call_pool(CURL *curl, struct pool_infos *pool,
                          const char *req, bool lp_scan, bool lp, int *err);
json_t *json_rpc_longpoll(CURL *curl, char *lp_url, struct pool_infos *pool,
                          const char *req, int *err);
json_t *json_load_url(char *cfg_url, json_error_t *err);
bool parse_pool_array(json_t *obj);
bool work_decode(const json_t *val, struct work *work);
bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen);

int share_result(int result, int pooln, double sharediff, const char *reason);
bool submit_upstream_work(CURL *curl, struct work *work);
bool get_mininginfo(CURL *curl, struct work *work);
bool get_upstream_work(CURL *curl, struct work *work);

#ifdef __cplusplus
}
#endif

#endif
