#ifndef __DAEMON_H__
#define __DAEMON_H__

#include <curl/curl.h>
#include <jansson.h>

// Forward declarations of types
struct work;
struct pool_infos;

#ifdef __cplusplus
extern "C" {
#endif

// External declarations needed
extern bool allow_gbt;
extern bool opt_quiet;
// Removed pools declaration to avoid linkage conflict
// extern struct pool_infos pools[];
extern const char *info_req;
extern const char *json_rpc_getwork;

// Forward declarations of functions
bool gbt_work_decode(const json_t *val, struct work *work);
json_t *json_rpc_call_pool(CURL *curl, struct pool_infos *pool, const char *rpc_req, 
                          bool lp_scan, bool lock, int *err);

bool get_blocktemplate(CURL *curl, struct work *work);

#ifdef __cplusplus
}
#endif

#endif // __DAEMON_H__
