/**
 * Functions which handle multiple pools data
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "constants.h"

#include "types.h"
#include "main.h"

// to move in main.h
extern bool allow_gbt;
extern bool allow_mininginfo;
extern bool check_dups;

extern double opt_max_diff;
extern double opt_max_rate;
extern int opt_scantime;
extern int opt_shares_limit;
extern int opt_time_limit;

extern char* rpc_url;
extern char* rpc_user;
extern char* rpc_pass;
extern char* short_url;

extern struct work _ALIGN(64) g_work;
extern struct stratum_ctx stratum;
extern pthread_mutex_t stratum_work_lock;
extern pthread_mutex_t stats_lock;
extern bool get_work(struct thr_info *thr, struct work *work);
extern bool stratum_need_reset;
extern time_t firstwork_time;

extern volatile time_t g_work_time;
extern volatile int pool_switch_count;
extern volatile bool pool_is_switching;
extern uint8_t conditional_state[MAX_GPUS];

extern double thr_hashrates[MAX_GPUS];

extern struct option options[];

#define CFG_NULL 0
#define CFG_POOL 1
struct opt_config_array {
	int cat;
	const char *name;     // json key
	const char *longname; // global opt name if different
} cfg_array_keys[] = {
	{ CFG_POOL, "url", NULL }, /* let this key first, increment pools */
	{ CFG_POOL, "user", NULL },
	{ CFG_POOL, "pass", NULL },
	{ CFG_POOL, "userpass", NULL },
	{ CFG_POOL, "name", "pool-name" },
	{ CFG_POOL, "algo", "pool-algo" },
	{ CFG_POOL, "scantime", "pool-scantime" },
	{ CFG_POOL, "max-diff", "pool-max-diff" },
	{ CFG_POOL, "max-rate", "pool-max-rate" },
	{ CFG_POOL, "disabled", "pool-disabled" },
	{ CFG_POOL, "time-limit", "pool-time-limit" },
	{ CFG_NULL, NULL, NULL }
};

bool conditional_pool_rotate = false;

// store current credentials in pools container
void pool_set_creds(int pooln)
{
	struct pool_infos *p = &pools[pooln];

	snprintf(p->url, sizeof(p->url), "%s", rpc_url);
	snprintf(p->short_url, sizeof(p->short_url), "%s", short_url);
	snprintf(p->user, sizeof(p->user), "%s", rpc_user);
	snprintf(p->pass, sizeof(p->pass), "%s", rpc_pass);

	if (!(p->status & POOL_ST_DEFINED)) {
		p->id = pooln;
		p->status |= POOL_ST_DEFINED;
		// init pool options as "unset"
		// until cmdline is fully parsed...
		p->max_diff = -1.;
		p->max_rate = -1.;
		p->scantime = -1;
		p->shares_limit = -1;
		p->time_limit = -1;

		p->allow_mininginfo = allow_mininginfo;
		p->allow_gbt = allow_gbt;
		p->check_dups = check_dups;

		p->status |= POOL_ST_DEFINED;
	}

	if (strlen(rpc_url)) {
		if (!strncasecmp(rpc_url, "stratum", 7))
			p->type = POOL_STRATUM;
		else /* if (!strncasecmp(rpc_url, "http", 4)) */
			p->type = POOL_GETWORK; // todo: or longpoll
		p->status |= POOL_ST_VALID;
	}
}

// fill the unset pools options with cmdline ones
void pool_init_defaults()
{
	struct pool_infos *p;
	for (int i=0; i<num_pools; i++) {
		p = &pools[i];
		if (p->max_diff == -1.) p->max_diff = opt_max_diff;
		if (p->max_rate == -1.) p->max_rate = opt_max_rate;
		if (p->scantime == -1) p->scantime = opt_scantime;
		if (p->shares_limit == -1) p->shares_limit = opt_shares_limit;
		if (p->time_limit == -1) p->time_limit = opt_time_limit;
	}
}

// attributes only set by a json pools config
void pool_set_attr(int pooln, const char* key, char* arg)
{
	struct pool_infos *p = &pools[pooln];
	if (!strcasecmp(key, "name")) {
		snprintf(p->name, sizeof(p->name), "%s", arg);
		return;
	}
	if (!strcasecmp(key, "scantime")) {
		p->scantime = atoi(arg);
		return;
	}
	if (!strcasecmp(key, "max-diff")) {
		p->max_diff = atof(arg);
		return;
	}
	if (!strcasecmp(key, "max-rate")) {
		p->max_rate = atof(arg);
		return;
	}
	if (!strcasecmp(key, "shares-limit")) {
		p->shares_limit = atoi(arg);
		return;
	}
	if (!strcasecmp(key, "time-limit")) {
		p->time_limit = atoi(arg);
		return;
	}
	if (!strcasecmp(key, "disabled")) {
		int removed = atoi(arg);
		if (removed) {
			p->status |= POOL_ST_REMOVED;
		}
		return;
	}
}

// pool switching code
bool pool_switch(int thr_id, int pooln)
{
	int prevn = cur_pooln;
	bool algo_switch = false;
	struct pool_infos *prev = &pools[cur_pooln];
	struct pool_infos* p = NULL;

	// save prev stratum connection infos (struct)
	if (prev->type & POOL_STRATUM) {
		// may not be the right moment to free,
		// to check if required on submit...
		stratum_free_job(&stratum);
		prev->stratum = stratum;
	}

	if (pooln < num_pools) {
		cur_pooln = pooln;
		p = &pools[cur_pooln];
	} else {
		applog(LOG_ERR, "Switch to inexistant pool %d!", pooln);
		return false;
	}

	// save global attributes
	prev->allow_mininginfo = allow_mininginfo;
	prev->allow_gbt = allow_gbt;
	prev->check_dups = check_dups;

	pthread_mutex_lock(&stratum_work_lock);

	free(rpc_user); rpc_user = strdup(p->user);
	free(rpc_pass); rpc_pass = strdup(p->pass);
	free(rpc_url);  rpc_url = strdup(p->url);

	short_url = p->short_url; // just a pointer, no alloc

	opt_scantime = p->scantime;
	opt_max_diff = p->max_diff;
	opt_max_rate = p->max_rate;
	opt_shares_limit = p->shares_limit;
	opt_time_limit = p->time_limit;

	want_stratum = have_stratum = (p->type & POOL_STRATUM) != 0;

	// yiimp stats reporting
	opt_stratum_stats = (strstr(p->pass, "stats") != NULL) || (strcmp(p->user, "benchmark") == 0);

	pthread_mutex_unlock(&stratum_work_lock);

	if (prevn != cur_pooln) {

		pool_switch_count++;
		net_diff = 0;
		g_work_time = 0;
		g_work.data[0] = 0;
		pool_is_switching = true;
		stratum_need_reset = true;
		// used to get the pool uptime
		firstwork_time = time(NULL);
		restart_threads();
		// reset wait states
		for (int n=0; n<opt_n_threads; n++)
			conditional_state[n] = false;

		// restore flags
		allow_gbt = p->allow_gbt;
		allow_mininginfo = p->allow_mininginfo;
		check_dups = p->check_dups;

		if (want_stratum) {

			// temporary... until stratum code cleanup
			stratum = p->stratum;
			stratum.pooln = cur_pooln;

			// unlock the stratum thread
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
			applog(LOG_BLUE, "Switch to stratum pool %d: %s", cur_pooln,
				strlen(p->name) ? p->name : p->short_url);
		} else {
			applog(LOG_BLUE, "Switch to pool %d: %s", cur_pooln,
				strlen(p->name) ? p->name : p->short_url);
		}

		// will unlock the longpoll thread on /LP url receive
		want_longpoll = (p->type & POOL_LONGPOLL) || !(p->type & POOL_STRATUM);
		if (want_longpoll) {
			pthread_mutex_lock(&stratum_work_lock);
			// will issue a lp_url request to unlock the longpoll thread
			have_longpoll = false;
			get_work(&thr_info[0], &g_work);
			pthread_mutex_unlock(&stratum_work_lock);
		}

	}

	return true;
}

// search available pool
int pool_get_first_valid(int startfrom)
{
	int next = 0;
	struct pool_infos *p;
	for (int i=0; i<num_pools; i++) {
		int pooln = (startfrom + i) % num_pools;
		p = &pools[pooln];
		if (!(p->status & POOL_ST_VALID))
			continue;
		if (p->status & (POOL_ST_DISABLED | POOL_ST_REMOVED))
			continue;
		next = pooln;
		break;
	}
	return next;
}

// switch to next available pool
bool pool_switch_next(int thr_id)
{
	if (num_pools > 1) {
		int pooln = pool_get_first_valid(cur_pooln+1);
		return pool_switch(thr_id, pooln);
	} else {
		// no switch possible
		if (!opt_quiet)
			applog(LOG_DEBUG, "No other pools to try...");
		return false;
	}
}

// seturl from api remote (deprecated)
bool pool_switch_url(char *params)
{
	int prevn = cur_pooln, nextn;
	parse_arg('o', params);
	// cur_pooln modified by parse_arg('o'), get new pool num
	nextn = cur_pooln;
	// and to handle the "hot swap" from current one...
	cur_pooln = prevn;
	if (nextn == prevn)
		return false;
	return pool_switch(-1, nextn);
}

// Parse pools array in json config
bool parse_pool_array(json_t *obj)
{
	size_t idx;
	json_t *p, *val;

	if (!json_is_array(obj))
		return false;

	// array of objects [ {}, {} ]
	json_array_foreach(obj, idx, p)
	{
		if (!json_is_object(p))
			continue;

		for (int i = 0; i < ARRAY_SIZE(cfg_array_keys); i++)
		{
			int opt = -1;
			char *s = NULL;
			if (cfg_array_keys[i].cat != CFG_POOL)
				continue;

			val = json_object_get(p, cfg_array_keys[i].name);
			if (!val)
				continue;

			for (int k = 0; k < options_count(); k++)
			{
				const char *alias = cfg_array_keys[i].longname;
				if (alias && !strcasecmp(options[k].name, alias)) {
					opt = k;
					break;
				}
				if (!alias && !strcasecmp(options[k].name, cfg_array_keys[i].name)) {
					opt = k;
					break;
				}
			}
			if (opt == -1)
				continue;

			if (json_is_string(val)) {
				s = strdup(json_string_value(val));
				if (!s)
					continue;

				// applog(LOG_DEBUG, "pool key %s '%s'", options[opt].name, s);
				parse_arg(options[opt].val, s);
				free(s);
			} else {
				// numeric or bool
				char buf[32] = { 0 };
				double d = 0.;
				if (json_is_true(val)) d = 1.;
				else if (json_is_integer(val))
					d = 1.0 * json_integer_value(val);
				else if (json_is_real(val))
					d = json_real_value(val);
				snprintf(buf, sizeof(buf)-1, "%f", d);
				// applog(LOG_DEBUG, "pool key %s '%f'", options[opt].name, d);
				parse_arg(options[opt].val, buf);
			}
		}
	}
	return true;
}

// debug stuff
void pool_dump_infos()
{
	struct pool_infos *p;
	if (opt_benchmark) return;
	for (int i=0; i<num_pools; i++) {
		p = &pools[i];
		applog(LOG_DEBUG, "POOL %01d: %s USER %s -s %d", i,
			p->short_url, p->user, p->scantime);
	}
}

bool wanna_mine(int thr_id)
{
    bool state = true;
    bool allow_pool_rotate = (thr_id == 0 && num_pools > 1 && !pool_is_switching);

    if (opt_max_temp > 0.0)
    {
#ifdef USE_WRAPNVML
        struct cgpu_info *cgpu = &thr_info[thr_id].gpu;
        float temp = gpu_temp(cgpu);
        if (temp > opt_max_temp)
        {
            if (!conditional_state[thr_id] && !opt_quiet)
                gpulog(LOG_INFO, thr_id, "temperature too high (%.0f°c), waiting...", temp);
            state = false;
        }
        else if (opt_max_temp > 0. && opt_resume_temp > 0. && conditional_state[thr_id] && temp > opt_resume_temp)
        {
            if (!thr_id && opt_debug)
                applog(LOG_DEBUG, "temperature did not reach resume value %.1f...", opt_resume_temp);
            state = false;
        }
#endif
    }
    if (opt_max_diff > 0.0 && net_diff > opt_max_diff)
    {
        int next = pool_get_first_valid(cur_pooln + 1);
        if (num_pools > 1 && pools[next].max_diff != pools[cur_pooln].max_diff && opt_resume_diff <= 0.)
            conditional_pool_rotate = allow_pool_rotate;
        if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
            applog(LOG_INFO, "network diff too high, waiting...");
        state = false;
    }
    else if (opt_max_diff > 0. && opt_resume_diff > 0. && conditional_state[thr_id] && net_diff > opt_resume_diff)
    {
        if (!thr_id && opt_debug)
            applog(LOG_DEBUG, "network diff did not reach resume value %.3f...", opt_resume_diff);
        state = false;
    }
    if (opt_max_rate > 0.0 && net_hashrate > opt_max_rate)
    {
        int next = pool_get_first_valid(cur_pooln + 1);
        if (pools[next].max_rate != pools[cur_pooln].max_rate && opt_resume_rate <= 0.)
            conditional_pool_rotate = allow_pool_rotate;
        if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
        {
            char rate[32];
            format_hashrate(opt_max_rate, rate);
            applog(LOG_INFO, "network hashrate too high, waiting %s...", rate);
        }
        state = false;
    }
    else if (opt_max_rate > 0. && opt_resume_rate > 0. && conditional_state[thr_id] && net_hashrate > opt_resume_rate)
    {
        if (!thr_id && opt_debug)
            applog(LOG_DEBUG, "network rate did not reach resume value %.3f...", opt_resume_rate);
        state = false;
    }
    conditional_state[thr_id] = (uint8_t)!state;
    return state;
}
