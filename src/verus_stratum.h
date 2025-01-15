#ifndef VERUS_STRATUM_H
#define VERUS_STRATUM_H

#include <jansson.h>
#include "stratum.h"
#include "types.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

// External declarations from main.h needed for this module
void bn_store_hash_target_ratio(uint32_t *hash, uint32_t *target, struct work *work, int nonce);

// Verus/Equihash specific functions
bool equi_stratum_notify(struct stratum_ctx *sctx, json_t *params);
bool equi_stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params);
bool equi_stratum_set_target(struct stratum_ctx *sctx, json_t *params);
bool equi_stratum_submit(struct pool_infos *pool, struct work *work);
void equi_work_set_target(struct work* work, double diff);
void equi_store_work_solution(struct work* work, uint32_t* hash, void* sol_data);
double verus_network_diff(struct work *work);
void calc_network_diff(struct work *work);

#ifdef __cplusplus
}
#endif

#endif // VERUS_STRATUM_H
