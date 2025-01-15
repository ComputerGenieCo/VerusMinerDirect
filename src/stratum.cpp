// System includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <stdbool.h>
#include <inttypes.h>
#include <pthread.h>
#include <errno.h>

// C++ standard library includes
#include <cmath>
#include <vector>
#include <array>
#include <string>
#include <algorithm>

// Project includes
#include "stratum.h"
#include "miner-config.h"
#include "logging.h"
#include "workio.h"
#include "main.h"
#include "daemon.h"
#include "verus_stratum.h"  // Add this include

// Add this constant near the top of the file after includes
#define JSON_SUBMIT_BUF_LEN 20480  // 20KB buffer for JSON submissions

// Forward declarations of external functions
extern "C" void *stratum_thread(void *userdata);
extern "C" bool handle_stratum_response(char *buf);
void restart_threads(void);
void workio_abort(void);
void proper_exit(int reason);
void hashlog_purge_old(void);
void stats_purge_old(void);
double hashlog_get_sharediff(char *job_id, int nonce_id, double sharediff);
int share_result(int result, int pooln, double sharediff, const char *reason);
bool stratum_gen_work(struct stratum_ctx *sctx, struct work *work);

// External variables declarations
extern pthread_mutex_t stratum_work_lock;
extern int opt_timeout;
extern bool opt_protocol;
extern bool want_longpoll;
extern bool have_longpoll;
extern bool have_stratum;
extern bool opt_benchmark;
extern bool submit_old;
extern bool check_dups;
extern bool opt_showdiff;
extern time_t firstwork_time;
extern int opt_retries;
extern int opt_fail_pause;
extern int num_pools;
extern bool opt_pool_failover;
extern double opt_difficulty;
extern struct thr_info *thr_info;
extern bool check_stratum_jobs;
extern pthread_mutex_t stratum_sock_lock;
extern pthread_mutex_t g_work_lock;
extern struct work g_work;
extern time_t g_work_time;
extern struct pool_infos pools[];
extern bool pool_on_hold;
extern volatile bool pool_is_switching;
extern volatile int pool_switch_count;
extern bool have_stratum;
extern bool check_dups;
extern bool conditional_pool_rotate;
extern struct stratum_ctx stratum;
extern double net_diff;
extern const char *opt_algo;
extern pthread_mutex_t stats_lock;
extern double thr_hashrates[];

// Global variables
bool stratum_need_reset = false;

// Utility functions

void diff_to_target_equi(uint32_t *target, double diff) {
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

// Core Stratum protocol functions
bool handle_stratum_response(char *buf) {
    json_t *val, *err_val, *res_val, *id_val;
    json_error_t err;
    struct timeval tv_answer, diff;
    int num = 0, job_nonce_id = 0;
    double sharediff = stratum.sharediff;
    bool ret = false;

    val = JSON_LOADS(buf, &err);
    if (!val)
    {
        applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
        goto out;
    }

    res_val = json_object_get(val, "result");
    err_val = json_object_get(val, "error");
    id_val = json_object_get(val, "id");

    if (!id_val || json_is_null(id_val))
        goto out;

    num = (int)json_integer_value(id_val);
    if (num < 4)
        goto out;

    job_nonce_id = num - 10;
    if (opt_showdiff && check_dups)
        sharediff = hashlog_get_sharediff(g_work.job_id, job_nonce_id, sharediff);

    gettimeofday(&tv_answer, NULL);
    timeval_subtract(&diff, &tv_answer, &stratum.tv_submit);
    stratum.answer_msec = (1000 * diff.tv_sec) + (uint32_t)(0.001 * diff.tv_usec);

    if (!res_val)
        goto out;
    share_result(json_is_true(res_val), stratum.pooln, sharediff,
                 err_val ? json_string_value(json_array_get(err_val, 1)) : NULL);

    ret = true;
out:
    if (val)
        json_decref(val);

    return ret;
}

// Work handling functions

bool work_decode(const json_t *val, struct work *work)
{
    int data_size, target_size = sizeof(work->target);
    int adata_sz, atarget_sz = ARRAY_SIZE(work->target);
    int i;

    data_size = 128;
    adata_sz = data_size / 4;

    if (!jobj_binary(val, "data", work->data, data_size))
    {
        json_t *obj = json_object_get(val, "data");
        int len = obj ? (int)strlen(json_string_value(obj)) : 0;
        if (!len || len > sizeof(work->data) * 2)
        {
            applog(LOG_ERR, "JSON invalid data (len %d <> %d)", len / 2, data_size);
            return false;
        }
        else
        {
            data_size = len / 2;
            if (!jobj_binary(val, "data", work->data, data_size))
            {
                applog(LOG_ERR, "JSON invalid data (len %d)", data_size);
                return false;
            }
        }
    }

    if (!jobj_binary(val, "target", work->target, target_size))
    {
        applog(LOG_ERR, "JSON invalid target");
        return false;
    }

    work->maxvote = 0;

    for (i = 0; i < adata_sz; i++)
        work->data[i] = le32dec(work->data + i);
    for (i = 0; i < atarget_sz; i++)
        work->target[i] = le32dec(work->target + i);

    if ((opt_showdiff || opt_max_diff > 0.) && !allow_mininginfo)
        calc_network_diff(work);

    work->targetdiff = target_to_diff(work->target);

    stratum_diff = work->targetdiff;

    work->tx_count = use_pok = 0;

    cbin2hex(work->job_id, (const char *)&work->data[17], 4);

    return true;
}

// Main stratum thread function
void *stratum_thread(void *userdata) {
    struct thr_info *mythr = (struct thr_info *)userdata;
    struct pool_infos *pool;
    stratum_ctx *ctx = &stratum;
    int pooln, switchn;
    char *s;

wait_stratum_url:
    stratum.url = (char *)tq_pop(mythr->q, NULL);
    if (!stratum.url)
        goto out;

    if (!pool_is_switching)
        applog(LOG_BLUE, "Starting on %s", stratum.url);

    ctx->pooln = pooln = cur_pooln;
    switchn = pool_switch_count;
    pool = &pools[pooln];

    pool_is_switching = false;
    stratum_need_reset = false;

    while (!abort_flag)
    {
        int failures = 0;

        if (stratum_need_reset)
        {
            stratum_need_reset = false;
            if (stratum.url)
                stratum_disconnect(&stratum);
            else
                stratum.url = strdup(pool->url);
        }

        while (!stratum.curl && !abort_flag)
        {
            pthread_mutex_lock(&g_work_lock);
            g_work_time = 0;
            g_work.data[0] = 0;
            pthread_mutex_unlock(&g_work_lock);
            restart_threads();

            if (!stratum_connect(&stratum, pool->url) ||
                !stratum_subscribe(&stratum) ||
                !stratum_authorize(&stratum, pool->user, pool->pass))
            {
                stratum_disconnect(&stratum);
                if (opt_retries >= 0 && ++failures > opt_retries)
                {
                    if (num_pools > 1 && opt_pool_failover)
                    {
                        applog(LOG_WARNING, "Stratum connect timeout, failover...");
                        pool_switch_next(-1);
                    }
                    else
                    {
                        applog(LOG_ERR, "...terminating workio thread");
                        workio_abort();
                        proper_exit(EXIT_CODE_POOL_TIMEOUT);
                        goto out;
                    }
                }
                if (switchn != pool_switch_count)
                    goto pool_switched;
                if (!opt_benchmark)
                    applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
                sleep(opt_fail_pause);
            }
        }

        if (switchn != pool_switch_count)
            goto pool_switched;

        if (stratum.job.job_id &&
            (!g_work_time || strncmp(stratum.job.job_id, g_work.job_id + 8, sizeof(g_work.job_id) - 8)))
        {
            pthread_mutex_lock(&g_work_lock);
            if (stratum_gen_work(&stratum, &g_work))
                g_work_time = time(NULL);
            if (stratum.job.clean)
            {
                static uint32_t last_block_height;
                if ((!opt_quiet || !firstwork_time) && stratum.job.height != last_block_height)
                {
                    last_block_height = stratum.job.height;
                    if (net_diff > 0.)
                        applog(LOG_BLUE, "%s block %d, diff %.3f", opt_algo,
                               stratum.job.height, net_diff);
                    else
                        applog(LOG_BLUE, "%s %s block %d", pool->short_url, opt_algo,
                               stratum.job.height);
                }
                restart_threads();
                if (check_dups || opt_showdiff)
                    hashlog_purge_old();
                stats_purge_old();
            }
            else if (opt_debug && !opt_quiet)
            {
                applog(LOG_BLUE, "%s asks job %d for block %d", pool->short_url,
                       strtoul(stratum.job.job_id, NULL, 16), stratum.job.height);
            }
            pthread_mutex_unlock(&g_work_lock);
        }

        if (switchn != pool_switch_count)
            goto pool_switched;

        if (!stratum_socket_full(&stratum, opt_timeout))
        {
            if (opt_debug)
                applog(LOG_WARNING, "Stratum connection timed out");
            s = NULL;
        }
        else
            s = stratum_recv_line(&stratum);

        if (switchn != pool_switch_count)
            goto pool_switched;

        if (!s)
        {
            stratum_disconnect(&stratum);
            if (!opt_quiet && !pool_on_hold)
                applog(LOG_WARNING, "Stratum connection interrupted");
            continue;
        }
        if (!stratum_handle_method(&stratum, s))
            handle_stratum_response(s);
        free(s);
    }

out:
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() died", __func__);

    return NULL;

pool_switched:
    stratum_disconnect(&(pools[pooln].stratum));
    if (stratum.url)
        free(stratum.url);
    stratum.url = NULL;
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() reinit...", __func__);
    goto wait_stratum_url;
}

int share_result(int result, int pooln, double sharediff, const char *reason)
{
    const char *flag;
    char suppl[32] = {0};
    char solved[16] = {0};
    char s[32] = {0};
    double hashrate = 0.;
    struct pool_infos *p = &pools[pooln];

    pthread_mutex_lock(&stats_lock);
    for (int i = 0; i < opt_n_threads; i++)
    {
        hashrate += stats_get_speed(i, thr_hashrates[i]);
    }
    pthread_mutex_unlock(&stats_lock);

    result ? p->accepted_count++ : p->rejected_count++;

    p->last_share_time = time(NULL);
    if (sharediff > p->best_share)
        p->best_share = sharediff;

    global_hashrate = llround(hashrate);

    format_hashrate(hashrate, s);
    if (opt_showdiff)
        snprintf(suppl, sizeof(suppl), "diff %.3f", sharediff);
    else
        snprintf(suppl, sizeof(suppl), "%.2f%%", 100. * p->accepted_count / (p->accepted_count + p->rejected_count));

    if (!net_diff || sharediff < net_diff)
    {
        flag = use_colors ? (result ? CL_GRN YES : CL_RED BOO)
                          : (result ? "(" YES ")" : "(" BOO ")");
    }
    else
    {
        p->solved_count++;
        flag = use_colors ? (result ? CL_GRN YAY : CL_RED BOO)
                          : (result ? "(" YAY ")" : "(" BOO ")");
        snprintf(solved, sizeof(solved), " solved: %u", p->solved_count);
    }

    applog(LOG_NOTICE, "accepted: %lu/%lu (%s), %s %s%s",
           p->accepted_count,
           p->accepted_count + p->rejected_count,
           suppl, s, flag, solved);
    if (reason)
    {
        applog(LOG_BLUE, "reject reason: %s", reason);
        if (!check_dups && strncasecmp(reason, "duplicate", 9) == 0)
        {
            applog(LOG_WARNING, "enabling duplicates check feature");
            check_dups = true;
            g_work_time = 0;
        }
    }
    return 1;
}

bool submit_upstream_work(CURL *curl, struct work *work)
{
    char s[512];
    struct pool_infos *pool = &pools[work->pooln];
    json_t *val, *res, *reason;
    bool stale_work = false;
    int idnonce = work->submit_nonce_id;

    if (pool->type & POOL_STRATUM && stratum.is_equihash)
    {
        struct work submit_work;
        memcpy(&submit_work, work, sizeof(struct work));
        if (equi_stratum_submit(pool, &submit_work))
            hashlog_remember_submit(&submit_work, submit_work.nonces[idnonce]);
        stratum.job.shares_count++;
        return true;
    }

    stale_work = work->height && work->height < g_work.height;
    if (have_stratum && !stale_work && !opt_submit_stale)
    {
        pthread_mutex_lock(&g_work_lock);
        if (strlen(work->job_id + 8))
            stale_work = strncmp(work->job_id + 8, g_work.job_id + 8, sizeof(g_work.job_id) - 8);
        if (stale_work)
        {
            pool->stales_count++;
            if (opt_debug)
                applog(LOG_DEBUG, "outdated job %s, new %s stales=%d",
                       work->job_id + 8, g_work.job_id + 8, pool->stales_count);
            if (!check_stratum_jobs && pool->stales_count > 5)
            {
                if (!opt_quiet)
                    applog(LOG_WARNING, "Enabled stratum stale jobs workaround");
                check_stratum_jobs = true;
                g_work_time = 0;
            }
        }
        pthread_mutex_unlock(&g_work_lock);
    }

    if (!have_stratum && !stale_work && allow_gbt)
    {
        struct work wheight = {0};
        if (get_blocktemplate(curl, &wheight))
        {
            if (work->height && work->height < wheight.height)
            {
                if (opt_debug)
                    applog(LOG_WARNING, "block %u was already solved", work->height);
                return true;
            }
        }
    }

    if (!submit_old && stale_work)
    {
        if (opt_debug)
            applog(LOG_WARNING, "stale work detected, discarding");
        return true;
    }

    if (pool->type & POOL_STRATUM)
    {
        uint32_t sent = 0;
        uint32_t ntime, nonce = work->nonces[idnonce];
        char *ntimestr, *noncestr, *xnonce2str;

        le32enc(&ntime, work->data[17]);
        le32enc(&nonce, work->data[19]);
        noncestr = bin2hex((const uchar *)(&nonce), 4);

        if (check_dups)
            sent = hashlog_already_submittted(work->job_id, nonce);
        if (sent > 0)
        {
            sent = (uint32_t)time(NULL) - sent;
            if (!opt_quiet)
            {
                applog(LOG_WARNING, "nonce %s was already sent %u seconds ago", noncestr, sent);
                hashlog_dump_job(work->job_id);
            }
            free(noncestr);
            g_work_time = 0;
            restart_threads();
            return true;
        }

        ntimestr = bin2hex((const uchar *)(&ntime), 4);

        xnonce2str = bin2hex(work->xnonce2, work->xnonce2_len);

        stratum.sharediff = work->sharediff[idnonce];

        if (net_diff && stratum.sharediff > net_diff && (opt_debug || opt_debug_diff))
            applog(LOG_INFO, "share diff: %.5f, possible block found!!!",
                   stratum.sharediff);
        else if (opt_debug_diff)
            applog(LOG_DEBUG, "share diff: %.5f (x %.1f)",
                   stratum.sharediff, work->shareratio[idnonce]);

        snprintf(s, sizeof(s), "{\"method\": \"mining.submit\", \"params\": ["
                   "\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":%u}",
                pool->user, work->job_id + 8, xnonce2str, ntimestr, noncestr, stratum.job.shares_count + 10);

        free(xnonce2str);
        free(ntimestr);
        free(noncestr);

        gettimeofday(&stratum.tv_submit, NULL);
        if (unlikely(!stratum_send_line(&stratum, s)))
        {
            applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
            return false;
        }

        if (check_dups || opt_showdiff)
            hashlog_remember_submit(work, nonce);
        stratum.job.shares_count++;
    }
    else
    {
        int data_size = 128;
        int adata_sz = data_size / sizeof(uint32_t);

        char *str = NULL;

        for (int i = 0; i < adata_sz; i++)
        {
            le32enc(work->data + i, work->data[i]);
        }
        str = bin2hex((uchar *)work->data, data_size);
        if (unlikely(!str))
        {
            applog(LOG_ERR, "submit_upstream_work OOM");
            return false;
        }

        snprintf(s, sizeof(s),
                "{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":10}\r\n",
                str);

        val = json_rpc_call_pool(curl, pool, s, false, false, NULL);
        if (unlikely(!val))
        {
            applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
            return false;
        }

        res = json_object_get(val, "result");
        reason = json_object_get(val, "reject-reason");
        if (!share_result(json_is_true(res), work->pooln, work->sharediff[0],
                          reason ? json_string_value(reason) : NULL))
        {
            if (check_dups)
                hashlog_purge_job(work->job_id);
        }

        json_decref(val);

        free(str);
    }

    return true;
}

bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen)
{
    const char *hexstr;
    json_t *tmp;

    tmp = json_object_get(obj, key);
    if (unlikely(!tmp))
    {
        applog(LOG_ERR, "JSON key '%s' not found", key);
        return false;
    }
    hexstr = json_string_value(tmp);
    if (unlikely(!hexstr))
    {
        applog(LOG_ERR, "JSON key '%s' is not a string", key);
        return false;
    }
    if (!hex2bin((uchar *)buf, hexstr, buflen))
        return false;

    return true;
}
