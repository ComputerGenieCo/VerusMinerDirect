#include <string>
#include <cmath>
#include <array>
#include <sys/time.h>
#include <cstring>
#include "verus_stratum.h"
#include "logging.h"
#include "main.h"  // Add this include for bn_store_hash_target_ratio and swab32

#define JSON_SUBMIT_BUF_LEN 20480  // 20KB buffer for JSON submissions

// External variable declarations
extern struct stratum_ctx stratum;
extern double net_diff;
extern pthread_mutex_t stratum_work_lock;
extern bool opt_protocol;
extern bool opt_debug;
extern bool opt_quiet;
extern time_t firstwork_time;

// Utility functions
inline double target_to_diff_verus(uint32_t target) {
    const unsigned exponent_diff = 8 * (0x20 - ((target >> 24) & 0xFF));
    const double significand = target & 0xFFFFFF;
    return std::ldexp(0x0f0f0f / significand, exponent_diff);
}

static void diff_to_target_equi(uint32_t *target, double diff) {
    uint64_t m;
    int k;

    for (k = 6; k > 0 && diff > 1.0; k--)
        diff /= 4294967296.0;

    m = (uint64_t)(4294901760.0 / diff);
    if (m == 0 && k == 6)
        memset(target, 0xff, 32);
    else {
        memset(target, 0, 32);
        target[k + 1] = (uint32_t)(m >> 8);
        target[k + 2] = (uint32_t)(m >> 40);
        for (k = 0; k < 28 && ((uint8_t*)target)[k] == 0; k++)
            ((uint8_t*)target)[k] = 0xff;
    }
}

double verus_network_diff(struct work *work) {
    uint32_t nbits = work->data[26];
    return target_to_diff_verus(nbits);
}

void equi_work_set_target(struct work* work, double diff) {
    diff_to_target_equi(work->target, diff);
    work->targetdiff = diff;
}

void calc_network_diff(struct work *work) {
    net_diff = verus_network_diff(work);
}

bool equi_stratum_set_target(struct stratum_ctx *sctx, json_t *params) {
    std::array<uint8_t, 32> target_bin, target_be = { 0 };
    const char *target_hex = json_string_value(json_array_get(params, 0));
    if (!target_hex || strlen(target_hex) == 0)
        return false;

    hex2bin(target_bin.data(), target_hex, 32);

    uint8_t *bits_start = nullptr;
    int filled = 0;
    for (int i = 0; i < 32; i++) {
        if (filled == 8) break;
        target_be[31 - i] = target_bin[i];
        if (target_bin[i]) {
            filled++;
            if(bits_start == nullptr)
                bits_start = &target_bin[i];
        }
    }

    int padding = &target_bin[31] - bits_start;
    uint32_t target_bits;
    uint8_t exponent = ((padding * 8 + 1) + 7) / 8;

    std::copy(target_be.begin() + exponent - 3, target_be.begin() + exponent, reinterpret_cast<uint8_t*>(&target_bits));
    target_bits |= (exponent << 24);

    std::copy(target_be.begin(), target_be.end(), sctx->job.extra);

    pthread_mutex_lock(&stratum_work_lock);
    sctx->next_diff = target_to_diff_verus(target_bits);
    pthread_mutex_unlock(&stratum_work_lock);

    return true;
}

bool equi_stratum_notify(struct stratum_ctx *sctx, json_t *params) {
    const char *job_id, *version, *prevhash, *coinb1, *coinb2, *nbits, *stime, *solution = NULL;
    size_t coinb1_size, coinb2_size;
    bool clean, ret = false;
    int ntime, i, p=0;
    job_id = json_string_value(json_array_get(params, p++));
    version = json_string_value(json_array_get(params, p++));
    prevhash = json_string_value(json_array_get(params, p++));
    coinb1 = json_string_value(json_array_get(params, p++));
    coinb2 = json_string_value(json_array_get(params, p++));
    stime = json_string_value(json_array_get(params, p++));
    nbits = json_string_value(json_array_get(params, p++));
    clean = json_is_true(json_array_get(params, p)); p++;
    solution = json_string_value(json_array_get(params, p++));

    if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !stime ||
        strlen(prevhash) != 64 || strlen(version) != 8 ||
        strlen(coinb1) != 64 || strlen(coinb2) != 64 ||
        strlen(nbits) != 8 || strlen(stime) != 8) {
        applog(LOG_ERR, "Stratum notify: invalid parameters");
        goto out;
    }
    hex2bin(&sctx->job.solution, solution, 1344);
    hex2bin((uchar *)&ntime, stime, 4);
    ntime = ntime - (int) time(0);
    if (ntime > sctx->srvtime_diff) {
        sctx->srvtime_diff = ntime;
        if (opt_protocol && ntime > 20)
            applog(LOG_DEBUG, "stratum time is at least %ds in the future", ntime);
    }

    pthread_mutex_lock(&stratum_work_lock);
    hex2bin(sctx->job.version, version, 4);
    hex2bin(sctx->job.prevhash, prevhash, 32);

    coinb1_size = strlen(coinb1) / 2;
    coinb2_size = strlen(coinb2) / 2;
    sctx->job.coinbase_size = coinb1_size + coinb2_size + sctx->xnonce1_size + sctx->xnonce2_size;

    sctx->job.coinbase = (uchar*) realloc(sctx->job.coinbase, sctx->job.coinbase_size);
    hex2bin(sctx->job.coinbase, coinb1, coinb1_size);
    hex2bin(sctx->job.coinbase + coinb1_size, coinb2, coinb2_size);

    sctx->job.xnonce2 = sctx->job.coinbase + coinb1_size + coinb2_size + sctx->xnonce1_size;
    if (!sctx->job.job_id || strcmp(sctx->job.job_id, job_id))
        memset(sctx->job.xnonce2, 0, sctx->xnonce2_size);
    memcpy(sctx->job.coinbase + coinb1_size + coinb2_size, sctx->xnonce1, sctx->xnonce1_size);

    for (i = 0; i < sctx->job.merkle_count; i++)
        free(sctx->job.merkle[i]);
    free(sctx->job.merkle);
    sctx->job.merkle = NULL;
    sctx->job.merkle_count = 0;

    free(sctx->job.job_id);
    sctx->job.job_id = strdup(job_id);

    hex2bin(sctx->job.nbits, nbits, 4);
    hex2bin(sctx->job.ntime, stime, 4);
    sctx->job.clean = clean;

    sctx->job.diff = sctx->next_diff;
    pthread_mutex_unlock(&stratum_work_lock);

    ret = true;
out:
    return ret;
}

bool equi_stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params) {
    char *s;
    json_t *val;
    bool ret;

    val = json_array_get(params, 0);
    if (val) {
        const char* data = json_string_value(val);
        if (data && strlen(data)) {
            char symbol[32] = { 0 };
            uint32_t height = 0;
            int ss = sscanf(data, "equihash %s block %u", symbol, &height);
            if (height && ss > 1) sctx->job.height = height;
        }
    }

    if (!id || json_is_null(id))
        return true;

    val = json_object();
    json_object_set(val, "id", id);
    json_object_set_new(val, "error", json_null());
    json_object_set_new(val, "result", json_true());
    s = json_dumps(val, 0);
    ret = stratum_send_line(sctx, s);
    json_decref(val);
    free(s);

    return ret;
}

void equi_store_work_solution(struct work* work, uint32_t* hash, void* sol_data) {
    int nonce = work->valid_nonces-1;
    memcpy(work->extra, sol_data, 1347);
    bn_store_hash_target_ratio(hash, work->target, work, nonce);
}

bool equi_stratum_submit(struct pool_infos *pool, struct work *work) {
    char s[JSON_SUBMIT_BUF_LEN];
    char timehex[16] = { 0 };
    std::string jobid, noncestr, solhex;
    int idnonce = work->submit_nonce_id;

    work->data[EQNONCE_OFFSET] = work->nonces[idnonce];
    unsigned char * nonce = (unsigned char*) (&work->data[27]);
    size_t nonce_len = 32 - stratum.xnonce1_size;
    noncestr = bin2hex(&nonce[stratum.xnonce1_size], nonce_len);

    solhex.resize(1344*2 + 64);
    if (solhex.empty() || noncestr.empty()) {
        applog(LOG_ERR, "unable to alloc share memory");
        return false;
    }
    cbin2hex(solhex.data(), (const char*) work->extra, 1347);

    std::string solHexRestore(128, '\0');
    cbin2hex(solHexRestore.data(), (const char*)&work->solution[8], 64);
    std::copy(solHexRestore.begin(), solHexRestore.end(), solhex.begin() + 6 + 16);

    jobid = work->job_id + 8;
    sprintf(timehex, "%08x", swab32(work->data[25]));

    snprintf(s, sizeof(s), "{\"method\":\"mining.submit\",\"params\":"
        "[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"], \"id\":%u}",
        pool->user, jobid.c_str(), timehex, noncestr.c_str(), solhex.c_str(),
        stratum.job.shares_count + 10);

    gettimeofday(&stratum.tv_submit, NULL);

    if(!stratum_send_line(&stratum, s)) {
        applog(LOG_ERR, "%s stratum_send_line failed", __func__);
        return false;
    }

    stratum.sharediff = work->sharediff[idnonce];
    stratum.job.shares_count++;

    return true;
}
