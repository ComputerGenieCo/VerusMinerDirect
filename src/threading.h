#ifndef THREADING_H
#define THREADING_H

#include <pthread.h>
#include <time.h>
#include "stratum.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Thread queue functions
struct thread_q;
struct thread_q *tq_new(void);
void tq_free(struct thread_q *tq);
bool tq_push(struct thread_q *tq, void *data);
void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
void tq_freeze(struct thread_q *tq);
void tq_thaw(struct thread_q *tq);

// Thread management functions 
void initialize_mutexes();
void initialize_mining_threads(int num_threads);
void set_thread_priority(int thr_id);
void set_cpu_affinity(int thr_id);
void drop_policy(void);
void affine_to_cpu(int id);
void *miner_thread(void *userdata);
void *miner_thread(void *userdata);
void *longpoll_thread(void *userdata);
bool wanna_mine(int thr_id);
void restart_threads(void);

extern bool conditional_pool_rotate;

#ifdef __cplusplus
}
#endif

#endif // THREADING_H

