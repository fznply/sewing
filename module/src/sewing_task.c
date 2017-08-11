
#include "sewing.h"

#include "sewing_crate.h"

#include "sewing_work.h"

#include "sewing_task.h"

static inline void sewing_task_init(sewing_task_ctx_t *ctx) {
    ctx->task_thread_id = syscall(__NR_gettid);
    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_task_init: %d", ctx->task_thread_id);
}

static inline void sewing_task_deliver(task_io_ctx_t *p_task_io_ctx) {
    sewing_task_ctx_t *ctx = p_task_io_ctx->sewing_task_ctx;

    ngx_buf_t *send_buf = p_task_io_ctx->send_buf;
    size_t buf_len = send_buf->last - send_buf->pos;
    ssize_t n;
    extern int errno;
    while (p_task_io_ctx->ready_write && 0 < buf_len) {
        n = write(p_task_io_ctx->fd, send_buf->pos, buf_len);
        // n = send(p_task_io_ctx->fd, send_buf->pos, buf_len, 0);
        if (0 < n) {
            if (n < buf_len) {
                p_task_io_ctx->ready_write = 0;
            }

            send_buf->pos += n;
            if (send_buf->pos == send_buf->last) {
                send_buf->pos = send_buf->start;
                send_buf->last = send_buf->start;
            }
            buf_len = send_buf->last - send_buf->pos;
        } else if (0 == n) { // write eof
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // TODO recall epoll_ctl
                p_task_io_ctx->ready_write = 0;
            } else {
                ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_task_deliver failed: %d", errno);
            }
            break;
        }
    }
}

static void sewing_task_write(struct epoll_event *ev) {
    task_io_ctx_t *p_task_io_ctx = (task_io_ctx_t *)ev->data.ptr;
    sewing_task_deliver(p_task_io_ctx);
}

static inline void sewing_task_do(sewing_task_ctx_t *ctx, sewing_rbtree_node_t *p) {
    ngx_http_sewing_loc_conf_t *conf = NULL;

    sewing_task_t sewing_task;
    sewing_task.p_sewing_rbtree_node = p;
    sewing_task.sewing_task_ctx = ctx;

    extern ngx_module_t ngx_http_sewing_module;
    conf = ngx_http_get_module_loc_conf(p->request, ngx_http_sewing_module);
    conf->sewing_crate->handler(&sewing_task);

    task_io_ctx_t *p_task_io_ctx = (task_io_ctx_t *)ctx->task_io_ctx;

    ngx_buf_t *send_buf = p_task_io_ctx->send_buf;
    size_t plen = sizeof(p);
    size_t buf_size = send_buf->end - send_buf->last;
    if (buf_size < plen) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_task_do failed");
        return;
    }
    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_task_send: %p", p);
    send_buf->last = ngx_cpymem(send_buf->last, &p, plen);

    sewing_task_deliver(p_task_io_ctx);
}

static void sewing_task_read(struct epoll_event *ev) {
    task_io_ctx_t *p_task_io_ctx = (task_io_ctx_t *)ev->data.ptr;
    sewing_task_ctx_t *ctx = p_task_io_ctx->sewing_task_ctx;

    ngx_buf_t *recv_buf = p_task_io_ctx->recv_buf;
    size_t buf_size = recv_buf->end - recv_buf->last;
    ssize_t n;
    extern int errno;
    while (p_task_io_ctx->ready_read && buf_size > 0) {
        n = read(p_task_io_ctx->fd, recv_buf->last, buf_size);
        // n = recv(p_task_io_ctx->fd, recv_buf->last, buf_size, 0);
        if (0 < n) {
            if (n < buf_size) {
                p_task_io_ctx->ready_read = 0;
            }

            recv_buf->last += n;
            buf_size = recv_buf->end - recv_buf->last;
        } else if (0 == n) { // read eof
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // TODO recall epoll_ctl
                p_task_io_ctx->ready_read = 0;
            } else {
                ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_task_read failed: %d", errno);
            }
            break;
        }
    }

    sewing_rbtree_node_t *p = NULL;
    size_t plen = sizeof(p);
    size_t buf_len = recv_buf->last - recv_buf->pos;

    while (buf_len >= plen) {
        p = *((sewing_rbtree_node_t **)(recv_buf->pos));
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_task_recv: %p", p);

        recv_buf->pos += plen;
        if (recv_buf->pos == recv_buf->last) {
            recv_buf->pos = recv_buf->start;
            recv_buf->last = recv_buf->start;
        }
        buf_len = recv_buf->last - recv_buf->pos;

        sewing_task_do(ctx, p);
    }
}

void *sewing_task_main(void *data) {
    sewing_task_ctx_t *ctx = (sewing_task_ctx_t *)data;
    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_task begin");

    sewing_task_init(ctx);

    task_io_ctx_t task_io_ctx;
    task_io_ctx.fd = ctx->yfd;
    ngx_nonblocking(task_io_ctx.fd);

    task_io_ctx.write_handler = sewing_task_write;
    task_io_ctx.read_handler = sewing_task_read;
    task_io_ctx.ready_write = 0;
    task_io_ctx.ready_read = 0;
    task_io_ctx.send_buf = ctx->send_buf;
    task_io_ctx.recv_buf = ctx->recv_buf;
    task_io_ctx.sewing_task_ctx = (void *)ctx;
    ctx->task_io_ctx = &task_io_ctx;

    size_t fd_num = 5;
    struct epoll_event event_array[fd_num];
    int epollfd = epoll_create(fd_num);

    struct epoll_event sewing_io_event;
    sewing_io_event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    sewing_io_event.data.ptr = (void *)&task_io_ctx;

    int ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, task_io_ctx.fd, &sewing_io_event);
    if (ret != 0) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_task add_task_io_event failed");
    }

    while (ctx->flag) {
        int n = epoll_wait(epollfd, event_array, fd_num, -1);
        int i = 0;
        for (i = 0; i < n; i++) {
            struct epoll_event *ev = &event_array[i];
            int i_events = ev->events;
            task_io_ctx_t *p_io_ctx = ev->data.ptr;
            if (i_events & EPOLLOUT) {
                p_io_ctx->ready_write = 1;
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_task_io ready_write");
                p_io_ctx->write_handler(ev);
            }
            if (i_events & EPOLLIN) {
                p_io_ctx->ready_read = 1;
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_task_io ready_read");
                p_io_ctx->read_handler(ev);
            }
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_task end");
}
