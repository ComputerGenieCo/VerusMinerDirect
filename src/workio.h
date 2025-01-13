#ifndef WORKIO_H
#define WORKIO_H

#include <pthread.h>
#include "types.h"
#include "main.h"

#ifdef __cplusplus
extern "C" {
#endif

enum workio_commands {
    WC_GET_WORK,
    WC_SUBMIT_WORK,
    WC_ABORT
};

struct workio_cmd {
    enum workio_commands cmd;
    struct thr_info *thr;
    union {
        struct work *work;
    } u;
    int pooln;
};

// Global variables shared between files
extern int work_thr_id;
extern int opt_fail_pause;
extern int opt_retries;

// Public interface
bool get_work(struct thr_info *thr, struct work *work);
bool submit_work(struct thr_info *thr, const struct work *work_in);
void workio_abort(void);
void *workio_thread(void *userdata);
void workio_cmd_free(struct workio_cmd *wc);

#ifdef __cplusplus
}
#endif

#endif /* WORKIO_H */
