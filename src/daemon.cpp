#include "daemon.h"
#include "main.h"  // Include main.h to access pools with C++ linkage
#include "logging.h"
#include "types.h"
#include "util.h"  // Include util.h to ensure json_rpc_call_pool is available

static const char *gbt_req =
    "{\"method\": \"getblocktemplate\", \"params\": [{"
    "}], \"id\":9}\r\n";

const char *info_req = "{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";
const char *json_rpc_getwork = "{\"method\":\"getwork\",\"params\":[],\"id\":0}\r\n";

bool get_blocktemplate(CURL *curl, struct work *work)
{
    struct pool_infos *pool = &pools[work->pooln];
    if (!allow_gbt)
        return false;

    int curl_err = 0;
    json_t *val = json_rpc_call_pool(curl, pool, gbt_req, false, false, &curl_err);

    if (!val && curl_err == -1)
    {
        allow_gbt = false;
        if (!opt_quiet)
        {
            applog(LOG_BLUE, "gbt not supported, block height notices disabled");
        }
        return false;
    }

    bool rc = gbt_work_decode(json_object_get(val, "result"), work);

    json_decref(val);

    return rc;
}
