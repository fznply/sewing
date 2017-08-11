#include "sewing.h"

static void sewing_event_handler(ngx_event_t *ev) {
    ngx_connection_t *c;
    sewing_module_ctx_t *ctx;

    c = ev->data;
    ctx = c->data;

    if (ev->timedout) {
        ev->delayed = 0;
        ev->timedout = 0;
        ctx->timeout_event_handler(ev);
    } else {
        if (ev->write) {
            ctx->write_event_handler(ev);
        } else {
            ctx->read_event_handler(ev);
        }
    }
}

ngx_int_t sewing_event_add(int socketpair_fd, sewing_module_ctx_t *ctx) {
    ngx_connection_t *c;
    ngx_uint_t level;
    ngx_int_t rc;

    c = ngx_get_connection(socketpair_fd, ctx->log);
    if (c == NULL) {
        return NGX_ERROR;
    }
    c->data = ctx;
    ctx->c = c;

    if (ngx_nonblocking(c->fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, ngx_socket_errno, ngx_nonblocking_n " failed");
        goto failed;
    }

    c->recv = ngx_recv;
    c->send = ngx_send;
    c->recv_chain = ngx_recv_chain;
    c->send_chain = ngx_send_chain;

    // TODO check the setting
    c->sendfile = 1;
    c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
    c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;

    c->read->handler = sewing_event_handler;
    c->write->handler = sewing_event_handler;

    c->read->log = ctx->log;
    c->write->log = ctx->log;

    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    if (ngx_add_conn(c) == NGX_ERROR) {
        goto failed;
    }

    return NGX_OK;

failed:
    ngx_close_connection(c);
    return NGX_ERROR;
}
