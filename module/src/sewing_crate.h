#ifndef _NGX_HTTP_SEWING_MOD_H_
#define _NGX_HTTP_SEWING_MOD_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

enum sewing_crate_type_t {

    sewing_mod_type_unset,
    sewing_mod_type_demo

};

typedef ngx_int_t (*sewing_crate_init_t)();
typedef ngx_int_t (*sewing_crate_handler_t)(void *p_sewing_task);

typedef struct {
    ngx_str_t type_str;
    enum sewing_crate_type_t type_enum;
    sewing_crate_init_t init;
    sewing_crate_handler_t handler;
} sewing_crate_t;

typedef struct {
    ngx_str_t type_str;
    enum sewing_crate_type_t type_enum;
    sewing_crate_t *sewing_crate;
} ngx_http_sewing_loc_conf_t;

#endif /* _NGX_HTTP_SEWING_MOD_H_ */
