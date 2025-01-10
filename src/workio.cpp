#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <curl/curl.h>

#include "miner.h"
#include "workio.h"

// External declarations
extern bool submit_upstream_work(CURL *curl, struct work *work);
extern bool get_upstream_work(CURL *curl, struct work *work);

// Add missing extern declarations at the top with the other externs:
extern int opt_fail_pause;
extern int opt_retries;

// External variables should match their declarations in miner.h
extern volatile bool abort_flag;
extern bool opt_debug_threads;
extern bool opt_pool_failover;
extern int work_thr_id;
extern struct thr_info *thr_info;
extern int num_pools;
extern bool opt_debug;
extern bool opt_quiet;
extern bool opt_protocol;
extern bool want_longpoll;
extern bool have_longpoll;
extern bool opt_benchmark;
extern int opt_timeout;
extern volatile int cur_pooln;
extern bool pool_is_switching;
extern struct pool_infos pools[];
extern int pool_switch_count;

void workio_cmd_free(struct workio_cmd *wc)
{
    if (!wc)
        return;

    switch (wc->cmd) {
    case WC_SUBMIT_WORK:
        aligned_free(wc->u.work);
        break;
    default: /* do nothing */
        break;
    }

    memset(wc, 0, sizeof(*wc));
    free(wc);
}

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
    struct work *ret_work;
    int failures = 0;

    ret_work = (struct work *)aligned_calloc(sizeof(struct work));
    if (!ret_work)
        return false;

    ret_work->pooln = wc->pooln;

    while (!get_upstream_work(curl, ret_work)) {
        if (unlikely(ret_work->pooln != cur_pooln)) {
            aligned_free(ret_work);
            tq_push(wc->thr->q, NULL);
            return true;
        }

        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "get_work failed");
            aligned_free(ret_work);
            return false;
        }

        applog(LOG_ERR, "get_work failed, retry after %d seconds",
            opt_fail_pause);
        sleep(opt_fail_pause);
    }

    if (!tq_push(wc->thr->q, ret_work))
        aligned_free(ret_work);

    return true;
}

static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
    int failures = 0;
    uint32_t pooln = wc->pooln;

    while (!submit_upstream_work(curl, wc->u.work)) {
        if (pooln != cur_pooln) {
            applog(LOG_DEBUG, "work from pool %u discarded", pooln);
            return true;
        }
        if (unlikely((opt_retries >= 0) && (++failures > opt_retries))) {
            applog(LOG_ERR, "...terminating workio thread");
            return false;
        }
        if (!opt_benchmark)
            applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
    }

    return true;
}

void *workio_thread(void *userdata)
{
    struct thr_info *mythr = (struct thr_info *)userdata;
    CURL *curl;
    bool ok = true;

    curl = curl_easy_init();
    if (unlikely(!curl)) {
        applog(LOG_ERR, "CURL initialization failed");
        return NULL;
    }

    while (ok && !abort_flag) {
        struct workio_cmd *wc;

        wc = (struct workio_cmd *)tq_pop(mythr->q, NULL);
        if (!wc) {
            ok = false;
            break;
        }

        switch (wc->cmd) {
        case WC_GET_WORK:
            ok = workio_get_work(wc, curl);
            break;
        case WC_SUBMIT_WORK:
            ok = workio_submit_work(wc, curl);
            break;
        case WC_ABORT:
        default:
            ok = false;
            break;
        }

        workio_cmd_free(wc);

        if (!ok && num_pools > 1 && opt_pool_failover) {
            if (opt_debug_threads)
                applog(LOG_DEBUG, "%s died, failover", __func__);
            ok = pool_switch_next(-1); 
            if (ok) continue;
        }
    }

    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() died", __func__);
    curl_easy_cleanup(curl);
    tq_freeze(mythr->q);
    return NULL;
}

void workio_abort()
{
    struct workio_cmd *wc;

    wc = (struct workio_cmd *)calloc(1, sizeof(*wc));
    if (!wc)
        return;

    wc->cmd = WC_ABORT;

    if (!tq_push(thr_info[work_thr_id].q, wc))
        workio_cmd_free(wc);
}

bool get_work(struct thr_info *thr, struct work *work)
{
    struct workio_cmd *wc;
    struct work *work_heap;

    if (opt_benchmark) {
        // Set up benchmark work
        memset(work->data, 0x55, 76);
        memset(work->data + 19, 0x00, 52);
        work->data[20] = 0x80000000;
        work->data[31] = 0x00000280;
        memset(work->target, 0x00, sizeof(work->target));
        return true;
    }

    wc = (struct workio_cmd *)calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->cmd = WC_GET_WORK;
    wc->thr = thr;
    wc->pooln = cur_pooln;

    if (!tq_push(thr_info[work_thr_id].q, wc)) {
        workio_cmd_free(wc);
        return false;
    }

    work_heap = (struct work *)tq_pop(thr->q, NULL);
    if (!work_heap)
        return false;

    memcpy(work, work_heap, sizeof(struct work));
    aligned_free(work_heap);

    return true;
}

bool submit_work(struct thr_info *thr, const struct work *work_in)
{
    struct workio_cmd *wc;

    wc = (struct workio_cmd *)calloc(1, sizeof(*wc));
    if (!wc)
        return false;

    wc->u.work = (struct work *)aligned_calloc(sizeof(*work_in));
    if (!wc->u.work)
        goto err_out;

    wc->cmd = WC_SUBMIT_WORK;
    wc->thr = thr;
    memcpy(wc->u.work, work_in, sizeof(struct work));
    wc->pooln = work_in->pooln;

    if (!tq_push(thr_info[work_thr_id].q, wc))
        goto err_out;

    return true;

err_out:
    workio_cmd_free(wc);
    return false;
}
