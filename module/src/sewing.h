#ifndef _NGX_HTTP_SEWING_MODULE_SEWING_H_
#define _NGX_HTTP_SEWING_MODULE_SEWING_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct sewing_list_s sewing_list_t;
struct sewing_list_s {
    sewing_list_t *next;
};

typedef struct {
    sewing_list_t node;
    char table_elt[0];
} sewing_list_table_ele_t;

typedef void (*sewing_event_handler_t)(ngx_event_t *ev);

typedef struct {
    ngx_log_t *log;
    ngx_connection_t *c;

    sewing_event_handler_t write_event_handler;
    sewing_event_handler_t read_event_handler;
    sewing_event_handler_t timeout_event_handler;

    ngx_buf_t *send_buf;
    ngx_buf_t *recv_buf;
} sewing_module_ctx_t;

ngx_int_t sewing_event_add(int socketpair_fd, sewing_module_ctx_t *ctx);

typedef struct {
    ngx_rbtree_node_t node;
    ngx_http_request_t *request;

    ngx_uint_t http_status;
    ngx_str_t *p_content_type;
    sewing_list_table_ele_t *p_headers;
    ngx_chain_t *p_body;

    ngx_buf_t buffer;
} sewing_rbtree_node_t;

typedef struct {
    int xfd;
    int yfd;

    int flag;
    ngx_log_t *log;

    ngx_buf_t *send_buf;
    ngx_buf_t *recv_buf;
    void *work_io_ctx;
} sewing_work_ctx_t;

void *sewing_work_main(void *data);

ngx_uint_t sewing_buff_size();
ngx_uint_t sewing_pool_size(ngx_uint_t buff_num);

#endif /* _NGX_HTTP_SEWING_MODULE_SEWING_H_ */
