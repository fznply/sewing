#ifndef _NGX_HTTP_SEWING_TASK_H_
#define _NGX_HTTP_SEWING_TASK_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef void (*task_io_handler_t)(struct epoll_event *ev);

typedef struct {
    int fd;

    task_io_handler_t write_handler;
    task_io_handler_t read_handler;

    int ready_write;
    int ready_read;

    ngx_buf_t *send_buf;
    ngx_buf_t *recv_buf;

    void *sewing_task_ctx;
} task_io_ctx_t;

typedef struct {
    void *p_sewing_rbtree_node;
    void *sewing_task_ctx;
} sewing_task_t;

#endif /* _NGX_HTTP_SEWING_TASK_H_ */
