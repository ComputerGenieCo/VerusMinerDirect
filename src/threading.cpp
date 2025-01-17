#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/resource.h>

#ifdef __linux
#include <sched.h>
#elif defined(__FreeBSD__)
#include <sys/cpuset.h>
#elif defined(WIN32)
#include <windows.h>
#endif

#include "threading.h"
#include "miner-config.h"
#include "logging.h"
#include "stratum.h"
#include "workio.h"
#include "daemon.h"

// External mutex declarations 
extern pthread_mutex_t applog_lock;
extern pthread_mutex_t stratum_sock_lock;
extern pthread_mutex_t stratum_work_lock;
extern pthread_mutex_t stats_lock;
extern pthread_mutex_t g_work_lock;
extern int opt_priority;
extern int num_cpus;
extern struct thr_info *thr_info;
extern bool opt_debug;  // Changed from int to bool to match config.h

// External variable declarations
extern int pool_switch_count;
extern volatile time_t g_work_time;
extern struct stratum_ctx stratum;
extern struct work g_work;
extern bool conditional_pool_rotate;
extern volatile bool pool_is_switching;
extern volatile bool pool_on_hold;
extern int app_exit_code;
extern double thr_hashrates[MAX_GPUS];

// External function declarations
void log_hash_rates(int thr_id, uint64_t loopcnt, time_t *tm_rate_log);

void initialize_mutexes()
{
    pthread_mutex_init(&applog_lock, NULL);
    pthread_mutex_init(&stratum_sock_lock, NULL);
    pthread_mutex_init(&stratum_work_lock, NULL);
    pthread_mutex_init(&stats_lock, NULL);
    pthread_mutex_init(&g_work_lock, NULL);
}

// Keep the thread queue implementation since it's needed by main.cpp

struct tq_ent {
    void *data;
    struct tq_ent *next;
    bool frozen;
};

// Keep all the thread queue functions (tq_new, tq_free, tq_push, tq_pop, etc.)

#ifdef __linux
void drop_policy(void) 
{
    struct sched_param param;
    param.sched_priority = 0;
#ifdef SCHED_IDLE
    if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
        sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

void affine_to_cpu(int id) 
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(id, &set);
#if !(defined(__ANDROID__) || (__ANDROID_API__ > 23))
    pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
#else
    sched_setaffinity(0, sizeof(&set), &set);
#endif
}
#elif defined(__FreeBSD__)
void drop_policy(void) {}
void affine_to_cpu(int id)
{
    cpuset_t set;
    CPU_ZERO(&set);
    CPU_SET(id, &set);
    cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(cpuset_t), &set);
}
#elif defined(WIN32)
void drop_policy(void) {}
static void affine_to_cpu_mask(int id, unsigned long mask)
{
    if (id == -1)
        SetProcessAffinityMask(GetCurrentProcess(), mask);
    else
        SetThreadAffinityMask(GetCurrentThread(), mask);
}
#else
void drop_policy(void) {}
static void affine_to_cpu_mask(int id, uint8_t mask) {}
#endif

void set_thread_priority(int thr_id)
{
    if (opt_priority > 0)
    {
        int prio = 2;
#ifndef WIN32
        prio = 0;
        switch (opt_priority)
        {
        case 0:
            prio = 15;
            break;
        case 1:
            prio = 5;
            break;
        case 2:
            prio = 0;
            break;
        case 3:
            prio = -1;
            break;
        case 4:
            prio = -10;
            break;
        case 5:
            prio = -15;
        }
        if (opt_debug)
            applog(LOG_DEBUG, "Thread %d priority %d (nice %d)",
                   thr_id, opt_priority, prio);
#endif
        setpriority(PRIO_PROCESS, 0, prio);
        drop_policy();
    }
}

void set_cpu_affinity(int thr_id)
{
    if (num_cpus > 1)
    {
        affine_to_cpu(thr_id);
    }
}

void restart_threads(void)
{
    if (opt_debug && !opt_quiet)
        applog(LOG_DEBUG, "%s", __FUNCTION__);

    for (int i = 0; i < opt_n_threads && work_restart; i++)
        work_restart[i].restart = 1;
}

void *miner_thread(void *userdata)
{
    struct thr_info *thr = (struct thr_info *)userdata;
    int switchn = pool_switch_count;
    int thr_id = thr->id;
    int dev_id = device_map[thr_id % MAX_GPUS];
    struct cgpu_info *cgpu = &thr_info[thr_id].gpu;
    struct work work;
    uint64_t loopcnt = 0;
    uint32_t max_nonce;
    uint32_t end_nonce = UINT32_MAX / opt_n_threads * (thr_id + 1) - (thr_id + 1);
    time_t tm_rate_log = 0;
    bool work_done = false;
    bool extrajob = false;
    char s[16];
    int rc = 0;

    memset(&work, 0, sizeof(work));

    set_thread_priority(thr_id);
    set_cpu_affinity(thr_id);

    if (num_cpus > 1)
    {
        affine_to_cpu(thr_id);
    }

    while (!abort_flag)
    {
        struct timeval tv_start, tv_end, diff;
        unsigned long hashes_done;
        uint32_t start_nonce;
        uint32_t scan_time = have_longpoll ? LP_SCANTIME : opt_scantime;
        uint64_t max64, minmax = 0x100000;
        int nodata_check_oft = 0;
        bool regen = false;

        int wcmplen = 76;
        int wcmpoft = 0;

        uint32_t *nonceptr = (uint32_t *)(((char *)work.data) + wcmplen);

        nonceptr = &work.data[EQNONCE_OFFSET];
        wcmplen = 4 + 32 + 32;

        if (have_stratum)
        {
            uint32_t sleeptime = 0;

            while (!work_done && time(NULL) >= (g_work_time + opt_scantime))
            {
                usleep(100 * 1000);
                if (sleeptime > 4)
                {
                    extrajob = true;
                    break;
                }
                sleeptime++;
            }
            if (sleeptime && opt_debug && !opt_quiet)
                applog(LOG_DEBUG, "sleeptime: %u ms", sleeptime * 100);
            pthread_mutex_lock(&g_work_lock);
            extrajob |= work_done;

            regen = (nonceptr[0] >= end_nonce);
            regen = regen || extrajob;

            if (regen)
            {
                work_done = false;
                extrajob = false;
                if (stratum_gen_work(&stratum, &g_work))
                    g_work_time = time(NULL);
            }
        }
        else
        {
            uint32_t secs = 0;
            pthread_mutex_lock(&g_work_lock);
            secs = (uint32_t)(time(NULL) - g_work_time);
            if (secs >= scan_time || nonceptr[0] >= (end_nonce - 0x100))
            {
                if (opt_debug && g_work_time && !opt_quiet)
                    applog(LOG_DEBUG, "work time %u/%us nonce %x/%x", secs, scan_time, nonceptr[0], end_nonce);
                if (unlikely(!get_work(thr, &g_work)))
                {
                    pthread_mutex_unlock(&g_work_lock);
                    if (switchn != pool_switch_count)
                    {
                        switchn = pool_switch_count;
                        continue;
                    }
                    else
                    {
                        applog(LOG_ERR, "work retrieval failed, exiting mining thread %d", thr->id);
                        goto out;
                    }
                }
                g_work_time = time(NULL);
                restart_threads();
            }
        }

        if (strcmp(work.job_id, g_work.job_id))
            stratum.job.shares_count = 0;

        if (!opt_benchmark && (g_work.height != work.height || memcmp(work.target, g_work.target, sizeof(work.target))))
        {
            if (opt_debug)
            {
                uint64_t target64 = g_work.target[7] * 0x100000000ULL + g_work.target[6];
                applog(LOG_DEBUG, "job %s target change: %llx (%.1f)", g_work.job_id, target64, g_work.targetdiff);
            }
            memcpy(work.target, g_work.target, sizeof(work.target));
            work.targetdiff = g_work.targetdiff;
            work.height = g_work.height;
        }

        if (memcmp(&work.data[wcmpoft], &g_work.data[wcmpoft], wcmplen))
        {
            memcpy(&work, &g_work, sizeof(struct work));
            nonceptr[0] = (UINT32_MAX / opt_n_threads) * thr_id;
        }
        else
            nonceptr[0]++;

        struct timeval tv;
        gettimeofday(&tv, NULL);
        
        uint32_t timestamp = (uint32_t)(tv.tv_sec ^ tv.tv_usec);
        uint32_t random_bits = (rand() & 0xFF) | ((rand() & 0xFF) << 8);
        nonceptr[2] = (timestamp & 0xFFFF0000) | (random_bits << 8) | (thr_id & 0xFF);

        pthread_mutex_unlock(&g_work_lock);

        loopcnt++;

        nodata_check_oft = 0;
        if (have_stratum && work.data[nodata_check_oft] == 0 && !opt_benchmark)
        {
            sleep(1);
            if (!thr_id)
                pools[cur_pooln].wait_time += 1;
            gpulog(LOG_DEBUG, thr_id, "no data");
            continue;
        }

        if (!wanna_mine(thr_id))
        {
            if (num_pools > 1 && conditional_pool_rotate)
            {
                if (!pool_is_switching)
                    pool_switch_next(thr_id);
                else if (time(NULL) - firstwork_time > 35)
                {
                    if (!opt_quiet)
                        applog(LOG_WARNING, "Pool switching timed out...");
                    if (!thr_id)
                        pools[cur_pooln].wait_time += 1;
                    pool_is_switching = false;
                }
                sleep(1);
                continue;
            }

            pool_on_hold = true;
            global_hashrate = 0;
            sleep(5);
            if (!thr_id)
                pools[cur_pooln].wait_time += 5;
            continue;
        }
        else
        {
        }

        pool_on_hold = false;

        work_restart[thr_id].restart = 0;

        if (have_stratum)
            max64 = LP_SCANTIME;
        else
            max64 = max(1, (int64_t)scan_time + g_work_time - time(NULL));

        if (opt_time_limit > 0 && firstwork_time)
        {
            int passed = (int)(time(NULL) - firstwork_time);
            int remain = (int)(opt_time_limit - passed);
            if (remain < 0)
            {
                if (thr_id != 0)
                {
                    sleep(1);
                    continue;
                }
                if (num_pools > 1 && pools[cur_pooln].time_limit > 0)
                {
                    if (!pool_is_switching)
                    {
                        if (!opt_quiet)
                            applog(LOG_INFO, "Pool mining timeout of %ds reached, rotate...", opt_time_limit);
                        pool_switch_next(thr_id);
                    }
                    else if (passed > 35)
                    {
                        applog(LOG_WARNING, "Pool switch to %d timed out...", cur_pooln);
                        if (!thr_id)
                            pools[cur_pooln].wait_time += 1;
                        pool_is_switching = false;
                    }
                    sleep(1);
                    continue;
                }
                app_exit_code = EXIT_CODE_TIME_LIMIT;
                abort_flag = true;
                if (opt_benchmark)
                {
                    char rate[32];
                    format_hashrate((double)global_hashrate, rate);
                    applog(LOG_NOTICE, "Benchmark: %s", rate);
                    usleep(200 * 1000);
                    fprintf(stderr, "%llu\n", (long long unsigned int)global_hashrate);
                }
                else
                {
                    applog(LOG_NOTICE, "Mining timeout of %ds reached, exiting...", opt_time_limit);
                }
                workio_abort();
                break;
            }
            if (remain < max64)
                max64 = remain;
        }

        if (opt_shares_limit > 0 && firstwork_time)
        {
            int64_t shares = (pools[cur_pooln].accepted_count + pools[cur_pooln].rejected_count);
            if (shares >= opt_shares_limit)
            {
                int passed = (int)(time(NULL) - firstwork_time);
                if (thr_id != 0)
                {
                    sleep(1);
                    continue;
                }
                if (num_pools > 1 && pools[cur_pooln].shares_limit > 0)
                {
                    if (!pool_is_switching)
                    {
                        if (!opt_quiet)
                            applog(LOG_INFO, "Pool shares limit of %d reached, rotate...", opt_shares_limit);
                        pool_switch_next(thr_id);
                    }
                    else if (passed > 35)
                    {
                        applog(LOG_WARNING, "Pool switch to %d timed out...", cur_pooln);
                        if (!thr_id)
                            pools[cur_pooln].wait_time += 1;
                        pool_is_switching = false;
                    }
                    sleep(1);
                    continue;
                }
                abort_flag = true;
                app_exit_code = EXIT_CODE_OK;
                applog(LOG_NOTICE, "Mining limit of %d shares reached, exiting...", opt_shares_limit);
                workio_abort();
                break;
            }
        }

        max64 *= (uint32_t)thr_hashrates[thr_id];

        if (max64 < minmax)
        {
            max64 = max(minmax - 1, max64);
        }

        max64 = min(UINT32_MAX, max64);

        start_nonce = nonceptr[0];

        if (end_nonce >= UINT32_MAX - 256)
            end_nonce = UINT32_MAX;

        if ((max64 + start_nonce) >= end_nonce)
            max_nonce = end_nonce;
        else
            max_nonce = (uint32_t)(max64 + start_nonce);

        if (unlikely(start_nonce > max_nonce))
        {
            max_nonce = end_nonce = UINT32_MAX;
        }

        work.scanned_from = start_nonce;

        gettimeofday(&tv_start, NULL);
        rc = scan_for_valid_hashes(thr_id, &work, max_nonce, &hashes_done);
        gettimeofday(&tv_end, NULL);

        if (abort_flag)
            break;

        if (work_restart[thr_id].restart)
            continue;

        timeval_subtract(&diff, &tv_end, &tv_start);

        if (cgpu && diff.tv_sec)
        {
            cgpu->monitor.sampling_flag = false;
        }

        if (diff.tv_usec || diff.tv_sec)
        {
            double dtime = (double)diff.tv_sec + 1e-6 * diff.tv_usec;

            double rate_factor = 1.0;

            if (dtime > 0.0)
            {
                pthread_mutex_lock(&stats_lock);
                thr_hashrates[thr_id] = hashes_done / dtime;
                thr_hashrates[thr_id] *= rate_factor;
                if (loopcnt > 2)
                    stats_remember_speed(thr_id, hashes_done, thr_hashrates[thr_id], (uint8_t)rc, work.height);
                pthread_mutex_unlock(&stats_lock);
            }
        }

        if (rc > 0)
            work.scanned_to = work.nonces[0];
        if (rc > 1)
            work.scanned_to = max(work.nonces[0], work.nonces[1]);
        else
        {
            work.scanned_to = max_nonce;
            if (opt_debug && opt_benchmark)
            {
                gpulog(LOG_DEBUG, thr_id, "ends=%08x range=%08x", nonceptr[0], (nonceptr[0] - start_nonce));
            }
            if (nonceptr[0] > UINT32_MAX - 64)
                nonceptr[0] = UINT32_MAX;
        }

        log_hash_rates(thr_id, loopcnt, &tm_rate_log);

        if (firstwork_time && thr_id == (opt_n_threads - 1))
        {
            double hashrate = 0.;
            pthread_mutex_lock(&stats_lock);
            for (int i = 0; i < opt_n_threads && thr_hashrates[i]; i++)
                hashrate += stats_get_speed(i, thr_hashrates[i]);
            pthread_mutex_unlock(&stats_lock);
            if (opt_benchmark && loopcnt > 2)
            {
                format_hashrate(hashrate, s);
                applog(LOG_NOTICE, "Total: %s", s);
            }

            pools[cur_pooln].work_time = (uint32_t)(time(NULL) - firstwork_time);

            global_hashrate = llround(hashrate);
        }

        if (firstwork_time == 0)
            firstwork_time = time(NULL);

        if (cgpu)
            cgpu->accepted += work.valid_nonces;

        if (rc > 0 && !opt_benchmark)
        {
            uint32_t curnonce = nonceptr[0];

            work.submit_nonce_id = 0;
            nonceptr[0] = work.nonces[0];
            if (!submit_work(thr, &work))
                break;
            nonceptr[0] = curnonce;

            if (!have_stratum && !have_longpoll)
            {
                pthread_mutex_lock(&g_work_lock);
                g_work_time = 0;
                pthread_mutex_unlock(&g_work_lock);
                continue;
            }

            if (rc > 1 && work.nonces[1])
            {
                work.submit_nonce_id = 1;
                nonceptr[0] = work.nonces[1];
                if (!submit_work(thr, &work))
                    break;
                nonceptr[0] = curnonce;
                work.nonces[1] = 0;
            }
        }
    }

out:

    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() died", __func__);
    tq_freeze(thr->q);
    return NULL;
}

void *longpoll_thread(void *userdata)
{
    struct thr_info *mythr = (struct thr_info *)userdata;
    struct pool_infos *pool;
    CURL *curl = NULL;
    char *hdr_path = NULL, *lp_url = NULL;
    const char *rpc_req = json_rpc_getwork;
    bool need_slash = false;
    int pooln, switchn;

    curl = curl_easy_init();
    if (unlikely(!curl))
    {
        applog(LOG_ERR, "%s() CURL init failed", __func__);
        goto out;
    }

wait_lp_url:
    hdr_path = (char *)tq_pop(mythr->q, NULL);
    if (!hdr_path)
        goto out;

    if (!(pools[cur_pooln].type & POOL_STRATUM))
    {
        pooln = cur_pooln;
        pool = &pools[pooln];
    }
    else
    {
        have_stratum = true;
    }

    switchn = pool_switch_count;

    if (strstr(hdr_path, "://"))
    {
        lp_url = hdr_path;
        hdr_path = NULL;
    }
    else
    {
        char *copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
        if (rpc_url[strlen(rpc_url) - 1] != '/')
            need_slash = true;

        lp_url = (char *)malloc(strlen(rpc_url) + strlen(copy_start) + 2);
        if (!lp_url)
            goto out;

        snprintf(lp_url, strlen(rpc_url) + strlen(copy_start) + 2, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
    }

    if (!pool_is_switching)
        applog(LOG_BLUE, "Long-polling on %s", lp_url);

    pool_is_switching = false;

longpoll_retry:

    while (!abort_flag)
    {
        json_t *val = NULL, *soval;
        int err = 0;

        if (opt_debug_threads)
            applog(LOG_DEBUG, "longpoll %d: %d count %d %d, switching=%d, have_stratum=%d",
                   pooln, cur_pooln, switchn, pool_switch_count, pool_is_switching, have_stratum);

        if (switchn != pool_switch_count)
            goto need_reinit;

        val = json_rpc_longpoll(curl, lp_url, pool, rpc_req, &err);
        if (have_stratum || switchn != pool_switch_count)
        {
            if (val)
                json_decref(val);
            goto need_reinit;
        }
        if (likely(val))
        {
            soval = json_object_get(json_object_get(val, "result"), "submitold");
            submit_old = soval ? json_is_true(soval) : false;
            pthread_mutex_lock(&g_work_lock);
            if (work_decode(json_object_get(val, "result"), &g_work))
            {
                restart_threads();
                if (!opt_quiet)
                {
                    char netinfo[64] = {0};
                    if (net_diff > 0.)
                    {
                        snprintf(netinfo, sizeof(netinfo), "diff %.3f", net_diff);
                    }
                    if (opt_showdiff)
                    {
                        snprintf(&netinfo[strlen(netinfo)], sizeof(netinfo) - strlen(netinfo), ", target %.3f", g_work.targetdiff);
                    }
                    if (g_work.height)
                        applog(LOG_BLUE, "%s block %u%s", opt_algo, g_work.height, netinfo);
                    else
                        applog(LOG_BLUE, "%s detected new block%s", short_url, netinfo);
                }
                g_work_time = time(NULL);
            }
            pthread_mutex_unlock(&g_work_lock);
            json_decref(val);
        }
        else
        {
            g_work_time = 0;
            if (err != CURLE_OPERATION_TIMEDOUT)
            {
                if (opt_debug_threads)
                    applog(LOG_DEBUG, "%s() err %d, retry in %s seconds",
                           __func__, err, opt_fail_pause);
                sleep(opt_fail_pause);
                goto longpoll_retry;
            }
        }
    }

out:
    have_longpoll = false;
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() died", __func__);

    free(hdr_path);
    free(lp_url);
    tq_freeze(mythr->q);
    if (curl)
        curl_easy_cleanup(curl);

    return NULL;

need_reinit:
    have_longpoll = false;
    if (opt_debug_threads)
        applog(LOG_DEBUG, "%s() reinit...", __func__);
    if (hdr_path)
        free(hdr_path);
    hdr_path = NULL;
    if (lp_url)
        free(lp_url);
    lp_url = NULL;
    goto wait_lp_url;
}

void initialize_mining_threads(int num_threads)
{
    struct thr_info *thr;
    int i;

    work_restart = (struct work_restart *)calloc(num_threads, sizeof(*work_restart));
    if (!work_restart)
        exit(EXIT_CODE_SW_INIT_ERROR);

    thr_info = (struct thr_info *)calloc(num_threads + 5, sizeof(*thr));
    if (!thr_info)
        exit(EXIT_CODE_SW_INIT_ERROR);

    longpoll_thr_id = num_threads + 1;
    thr = &thr_info[longpoll_thr_id];
    thr->id = longpoll_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        exit(EXIT_CODE_SW_INIT_ERROR);

    if (unlikely(pthread_create(&thr->pth, NULL, longpoll_thread, thr)))
    {
        applog(LOG_ERR, "longpoll thread create failed");
        exit(EXIT_CODE_SW_INIT_ERROR);
    }

    stratum_thr_id = num_threads + 2;
    thr = &thr_info[stratum_thr_id];
    thr->id = stratum_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        exit(EXIT_CODE_SW_INIT_ERROR);

    if (unlikely(pthread_create(&thr->pth, NULL, stratum_thread, thr)))
    {
        applog(LOG_ERR, "stratum thread create failed");
        exit(EXIT_CODE_SW_INIT_ERROR);
    }

    work_thr_id = num_threads;
    thr = &thr_info[work_thr_id];
    thr->id = work_thr_id;
    thr->q = tq_new();
    if (!thr->q)
        exit(EXIT_CODE_SW_INIT_ERROR);

    if (pthread_create(&thr->pth, NULL, workio_thread, thr))
    {
        applog(LOG_ERR, "workio thread create failed");
        exit(EXIT_CODE_SW_INIT_ERROR);
    }

    if (want_stratum && have_stratum)
    {
        tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
    }

    if (opt_api_port)
    {
        api_thr_id = num_threads + 3;
        thr = &thr_info[api_thr_id];
        thr->id = api_thr_id;
        thr->q = tq_new();
        if (!thr->q)
            exit(EXIT_CODE_SW_INIT_ERROR);

        if (unlikely(pthread_create(&thr->pth, NULL, api_thread, thr)))
        {
            applog(LOG_ERR, "api thread create failed");
            exit(EXIT_CODE_SW_INIT_ERROR);
        }
    }

    for (i = 0; i < num_threads; i++)
    {
        thr = &thr_info[i];

        thr->id = i;
        thr->gpu.thr_id = i;
        thr->gpu.gpu_id = (uint8_t)device_map[i];
        thr->q = tq_new();
        if (!thr->q)
            exit(EXIT_CODE_SW_INIT_ERROR);

        pthread_mutex_init(&thr->gpu.monitor.lock, NULL);
        pthread_cond_init(&thr->gpu.monitor.sampling_signal, NULL);

        if (unlikely(pthread_create(&thr->pth, NULL, miner_thread, thr)))
        {
            applog(LOG_ERR, "thread %d create failed", i);
            exit(EXIT_CODE_SW_INIT_ERROR);
        }
    }

    applog(LOG_INFO, "%d miner thread%s started, using '%s' algorithm.",
           num_threads, num_threads > 1 ? "s" : "", opt_algo);
}
