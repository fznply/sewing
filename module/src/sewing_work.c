#include "sewing.h"

#include "sewing_work.h"

static char resp_body[] = { "<html><p>hello world</p></html>\n" };
static ngx_str_t s_cntype_str = ngx_string("text/html");

void assign_greet_reponse(sewing_rbtree_node_t *p) {
    p->p_content_type = &s_cntype_str;

    p->p_body = (ngx_chain_t *)p->buffer.last;
    p->buffer.last += sizeof(ngx_chain_t);

    ngx_buf_t *b = (ngx_buf_t *)p->buffer.last;
    p->buffer.last += sizeof(ngx_buf_t);

    p->p_body->buf = b;
    p->p_body->next = NULL;

    b->pos = p->buffer.last;
    p->buffer.last = ngx_cpymem(p->buffer.last, resp_body, sizeof(resp_body));
    b->last = p->buffer.last;

    b->start = b->pos;
    b->end = b->last;

    b->memory = 1;
    b->last_buf = 1;
}

#define TASK_THREAD_NUM 64

static work_io_ctx_t upstream_ctx;
static ngx_pool_t *s_mem_pool;
static ngx_atomic_int_t s_work_thread_id;
static int last_task_thread_index;

static work_io_ctx_t downstream_ctxs[TASK_THREAD_NUM];
static pthread_t sewing_task_threads[TASK_THREAD_NUM];
static sewing_task_ctx_t sewing_task_ctxs[TASK_THREAD_NUM];

static inline void sewing_work_init(sewing_work_ctx_t *ctx) {
    s_mem_pool = ngx_create_pool(sewing_pool_size(4 * TASK_THREAD_NUM) + 1024 * 1024 * 4, ctx->log);
    if (s_mem_pool == NULL) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work_init create mem_pool failed");
        return;
    }

    s_work_thread_id = syscall(__NR_gettid);
    last_task_thread_index = 0;

    int i = 0;
    for (i = 0; i < TASK_THREAD_NUM; i++) {
        int fd[2];
        int xfd, yfd;
        int r = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
        if (r < 0) {
            ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work_init create socketpair failed");
        }
        xfd = fd[0];
        yfd = fd[1];

        sewing_task_ctx_t *p_sewing_task_ctx = &sewing_task_ctxs[i];
        p_sewing_task_ctx->xfd = xfd;
        p_sewing_task_ctx->yfd = yfd;

        p_sewing_task_ctx->flag = 1;
        p_sewing_task_ctx->log = ctx->log;

        p_sewing_task_ctx->task_thread_index = i;

        ngx_buf_t *buf = ngx_palloc(s_mem_pool, sizeof(ngx_buf_t));
        ngx_uint_t buf_size = sewing_buff_size();
        buf->start = ngx_palloc(s_mem_pool, buf_size);
        buf->end = buf->start + buf_size;
        buf->pos = buf->start;
        buf->last = buf->start;
        buf->memory = 1;
        p_sewing_task_ctx->send_buf = buf;

        buf = ngx_palloc(s_mem_pool, sizeof(ngx_buf_t));
        buf_size = sewing_buff_size();
        buf->start = ngx_palloc(s_mem_pool, buf_size);
        buf->end = buf->start + buf_size;
        buf->pos = buf->start;
        buf->last = buf->start;
        buf->memory = 1;
        p_sewing_task_ctx->recv_buf = buf;

        pthread_create(&sewing_task_threads[i], NULL, sewing_task_main, p_sewing_task_ctx);
    }
}

static inline void sewing_work_exit(sewing_work_ctx_t *ctx) {
    int i = 0;
    for (i = 0; i < TASK_THREAD_NUM; i++) {
        sewing_task_ctx_t *p_sewing_task_ctx = &sewing_task_ctxs[i];
        p_sewing_task_ctx->flag = 0;
    }
    for (i = 0; i < TASK_THREAD_NUM; i++) {
        pthread_join(sewing_task_threads[i], NULL);
    }
}

static inline void sewing_work_deliver(work_io_ctx_t *p_work_io_ctx) {
    sewing_work_ctx_t *ctx = p_work_io_ctx->sewing_work_ctx;

    ngx_buf_t *send_buf = p_work_io_ctx->send_buf;
    size_t buf_len = send_buf->last - send_buf->pos;
    ssize_t n;
    extern int errno;
    while (p_work_io_ctx->ready_write && 0 < buf_len) {
        n = write(p_work_io_ctx->fd, send_buf->pos, buf_len);
        // n = send(p_work_io_ctx->fd, send_buf->pos, buf_len, 0);
        if (0 < n) {
            if (n < buf_len) {
                p_work_io_ctx->ready_write = 0;
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
                p_work_io_ctx->ready_write = 0;
            } else {
                ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work_deliver failed: %d", errno);
            }
            break;
        }
    }
}

static void sewing_work_write(struct epoll_event *ev) {
    work_io_ctx_t *p_work_io_ctx = (work_io_ctx_t *)ev->data.ptr;
    sewing_work_deliver(p_work_io_ctx);
}

static inline void do_greet_task(sewing_work_ctx_t *ctx, sewing_rbtree_node_t *p) {

    assign_greet_reponse(p);

    work_io_ctx_t *p_work_io_ctx = (work_io_ctx_t *)ctx->work_io_ctx;

    ngx_buf_t *send_buf = p_work_io_ctx->send_buf;
    size_t plen = sizeof(p);
    size_t buf_size = send_buf->end - send_buf->last;
    if (buf_size < plen) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work_send_greet failed");
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work_send_greet: %p", p);

    send_buf->last = ngx_cpymem(send_buf->last, &p, plen);
    sewing_work_deliver(p_work_io_ctx);
}

static inline void downstream_recv(work_io_ctx_t *p_work_io_ctx, ngx_buf_t *recv_buf) {
    sewing_work_ctx_t *ctx = p_work_io_ctx->sewing_work_ctx;
    work_io_ctx_t *upstream_ctx = (work_io_ctx_t *)ctx->work_io_ctx;

    sewing_rbtree_node_t *p = NULL;
    size_t plen = sizeof(p);
    size_t buf_len = recv_buf->last - recv_buf->pos;

    while (buf_len >= plen) {
        p = *((sewing_rbtree_node_t **)(recv_buf->pos));
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work_downstream_recv: %p", p);

        recv_buf->pos += plen;
        if (recv_buf->pos == recv_buf->last) {
            recv_buf->pos = recv_buf->start;
            recv_buf->last = recv_buf->start;
        }
        buf_len = recv_buf->last - recv_buf->pos;

        upstream_ctx->send_buf->last = ngx_cpymem(upstream_ctx->send_buf->last, &p, plen);
        sewing_work_deliver(upstream_ctx);
    }
}

static inline void do_send_task(sewing_work_ctx_t *ctx, sewing_rbtree_node_t *p) {
    int i = last_task_thread_index;
    work_io_ctx_t *p_work_io_ctx = &downstream_ctxs[i];

    ngx_buf_t *send_buf = p_work_io_ctx->send_buf;
    size_t plen = sizeof(p);
    size_t buf_size = send_buf->end - send_buf->last;
    if (buf_size < plen) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work_send_task failed");
        return;
    }

    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work_send_task: %p", p);

    send_buf->last = ngx_cpymem(send_buf->last, &p, plen);
    sewing_work_deliver(p_work_io_ctx);

    last_task_thread_index = (i + 1) % TASK_THREAD_NUM;
}

static inline void sewing_work_do(sewing_work_ctx_t *ctx, sewing_rbtree_node_t *p) {
    if (TASK_THREAD_NUM < 1) {
        do_greet_task(ctx, p);
    } else {
        do_send_task(ctx, p);
    }
}

static inline void upstream_recv(work_io_ctx_t *p_work_io_ctx, ngx_buf_t *recv_buf) {
    sewing_work_ctx_t *ctx = p_work_io_ctx->sewing_work_ctx;
    sewing_rbtree_node_t *p = NULL;
    size_t plen = sizeof(p);
    size_t buf_len = recv_buf->last - recv_buf->pos;

    while (buf_len >= plen) {
        p = *((sewing_rbtree_node_t **)(recv_buf->pos));
        ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work_upstream_recv: %p", p);

        recv_buf->pos += plen;
        if (recv_buf->pos == recv_buf->last) {
            recv_buf->pos = recv_buf->start;
            recv_buf->last = recv_buf->start;
        }
        buf_len = recv_buf->last - recv_buf->pos;

        sewing_work_do(ctx, p);
    }
}

static void sewing_work_read(struct epoll_event *ev) {
    work_io_ctx_t *p_work_io_ctx = (work_io_ctx_t *)ev->data.ptr;
    sewing_work_ctx_t *ctx = p_work_io_ctx->sewing_work_ctx;

    ngx_buf_t *recv_buf = p_work_io_ctx->recv_buf;
    size_t buf_size = recv_buf->end - recv_buf->last;
    ssize_t n;
    extern int errno;
    while (p_work_io_ctx->ready_read && buf_size > 0) {
        n = read(p_work_io_ctx->fd, recv_buf->last, buf_size);
        // n = recv(p_work_io_ctx->fd, recv_buf->last, buf_size, 0);
        if (0 < n) {
            if (n < buf_size) {
                p_work_io_ctx->ready_read = 0;
            }

            recv_buf->last += n;
            buf_size = recv_buf->end - recv_buf->last;
        } else if (0 == n) { // read eof
            break;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) { // TODO recall epoll_ctl
                p_work_io_ctx->ready_read = 0;
            } else {
                ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work_read failed: %d", errno);
            }
            break;
        }
    }
    switch (p_work_io_ctx->sewing_io_type) {
        case sewing_io_type_upstream:
            upstream_recv(p_work_io_ctx, recv_buf);
            break;
        case sewing_io_type_downstream:
            downstream_recv(p_work_io_ctx, recv_buf);
            break;
    }
}

void *sewing_work_main(void *data) {
    sewing_work_ctx_t *ctx = (sewing_work_ctx_t *)data;
    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work begin");

    sewing_work_init(ctx);

    upstream_ctx.fd = ctx->yfd;
    ngx_nonblocking(upstream_ctx.fd);

    upstream_ctx.write_handler = sewing_work_write;
    upstream_ctx.read_handler = sewing_work_read;
    upstream_ctx.ready_write = 0;
    upstream_ctx.ready_read = 0;
    upstream_ctx.send_buf = ctx->send_buf;
    upstream_ctx.recv_buf = ctx->recv_buf;
    upstream_ctx.sewing_io_type = sewing_io_type_upstream;
    upstream_ctx.sewing_work_ctx = (void *)ctx;
    ctx->work_io_ctx = &upstream_ctx;

    size_t fd_num = TASK_THREAD_NUM + 10;
    struct epoll_event event_array[fd_num];
    int epollfd = epoll_create(fd_num);

    struct epoll_event sewing_io_event;
    sewing_io_event.events = EPOLLIN | EPOLLOUT | EPOLLET;
    sewing_io_event.data.ptr = (void *)&upstream_ctx;

    int ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, upstream_ctx.fd, &sewing_io_event);
    if (ret != 0) {
        ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work add_upstream_event failed");
    }

    int i = 0;
    for (i = 0; i < TASK_THREAD_NUM; i++) {
        work_io_ctx_t *p_work_io_ctx = &downstream_ctxs[i];
        p_work_io_ctx->fd = sewing_task_ctxs[i].xfd;
        ngx_nonblocking(p_work_io_ctx->fd);

        p_work_io_ctx->write_handler = sewing_work_write;
        p_work_io_ctx->read_handler = sewing_work_read;
        p_work_io_ctx->ready_write = 0;
        p_work_io_ctx->ready_read = 0;

        ngx_buf_t *buf = ngx_palloc(s_mem_pool, sizeof(ngx_buf_t));
        ngx_uint_t buf_size = sewing_buff_size();
        buf->start = ngx_palloc(s_mem_pool, buf_size);
        buf->end = buf->start + buf_size;
        buf->pos = buf->start;
        buf->last = buf->start;
        buf->memory = 1;
        p_work_io_ctx->send_buf = buf;

        buf = ngx_palloc(s_mem_pool, sizeof(ngx_buf_t));
        buf_size = sewing_buff_size();
        buf->start = ngx_palloc(s_mem_pool, buf_size);
        buf->end = buf->start + buf_size;
        buf->pos = buf->start;
        buf->last = buf->start;
        buf->memory = 1;
        p_work_io_ctx->recv_buf = buf;

        p_work_io_ctx->sewing_io_type = sewing_io_type_downstream;
        p_work_io_ctx->sewing_work_ctx = (void *)ctx;

        sewing_io_event.events = EPOLLIN | EPOLLOUT | EPOLLET;
        sewing_io_event.data.ptr = (void *)p_work_io_ctx;
        int ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, p_work_io_ctx->fd, &sewing_io_event);
        if (ret != 0) {
            ngx_log_error(NGX_LOG_EMERG, ctx->log, 0, "sewing_work add_downstream_event failed");
        }
    }

    while (ctx->flag) {
        int n = epoll_wait(epollfd, event_array, fd_num, -1);
        int i = 0;
        for (i = 0; i < n; i++) {
            struct epoll_event *ev = &event_array[i];
            int i_events = ev->events;
            work_io_ctx_t *p_work_io_ctx = ev->data.ptr;

            if (i_events & EPOLLOUT) {
                p_work_io_ctx->ready_write = 1;
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work ready_write");
                p_work_io_ctx->write_handler(ev);
            }
            if (i_events & EPOLLIN) {
                p_work_io_ctx->ready_read = 1;
                ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work ready_read");
                p_work_io_ctx->read_handler(ev);
            }
        }
    }

    close(epollfd);
    sewing_work_exit(ctx);

    ngx_log_error(NGX_LOG_NOTICE, ctx->log, 0, "sewing_work end");

    return NULL;
    /* this function is executed in a separate thread */
}
