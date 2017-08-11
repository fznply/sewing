#include "sewing_api.h"

static ngx_str_t resp_body = ngx_string("<html><p>demo resp</p></html>\n");

ngx_int_t crate_demo_init() {
    return NGX_OK;
}

ngx_int_t crate_demo_handler(void *p_sewing_task) {
    sewing_task_t *task = p_sewing_task;
    sewing_add_resp_header(task, "Demo-Key", "demo-value");
    sewing_set_resp_body(task, resp_body.data, resp_body.len);
    return NGX_DONE;
}
