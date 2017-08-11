#ifndef _NGX_HTTP_SEWING_WORK_H_
#define _NGX_HTTP_SEWING_WORK_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

enum sewing_io_type_t { sewing_io_type_upstream, sewing_io_type_downstream };

typedef void (*sewing_io_handler_t)(struct epoll_event *ev);

typedef struct {
    int fd;

    sewing_io_handler_t write_handler;
    sewing_io_handler_t read_handler;

    int ready_write;
    int ready_read;

    ngx_buf_t *send_buf;
    ngx_buf_t *recv_buf;

    enum sewing_io_type_t sewing_io_type;

    void *sewing_work_ctx;
} work_io_ctx_t;

typedef struct {
    int xfd;
    int yfd;

    int flag;
    ngx_log_t *log;

    ngx_buf_t *send_buf;
    ngx_buf_t *recv_buf;

    ngx_atomic_int_t task_thread_id;
    int task_thread_index;

    void *task_io_ctx;
} sewing_task_ctx_t;

void *sewing_task_main(void *data);

#endif /* _NGX_HTTP_SEWING_WORK_H_ */
