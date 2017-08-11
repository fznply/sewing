#include "sewing_crate.h"

ngx_int_t crate_demo_init();
ngx_int_t crate_demo_handler(void *p_sewing_task);

sewing_crate_t sewing_crates[] = {

    { ngx_string("demo"), sewing_mod_type_demo, crate_demo_init, crate_demo_handler }

};

ngx_uint_t sewing_crate_num = sizeof(sewing_crates) / sizeof(sewing_crate_t);
