#include <pthread.h>

#include "sewing.h"

#include "sewing_crate.h"

#define SEWING_REQUEST_TIMEOUT_SEC 6
#define SEWING_REQUEST_TIMEOUT_MSEC 6000
#define SEWING_REQUEST_NUM_WAIT_MAX 360000
#define SEWING_RESPONSE_BUFFER_SIZE 2048

static sewing_work_ctx_t *sewing_work_ctx = NULL;
static sewing_module_ctx_t *worker_sewing_ctx = NULL;
static pthread_t sewing_work_thread;

static void worker_sewing_read_handler(ngx_event_t *ev);
static void worker_sewing_write_handler(ngx_event_t *ev);
static void worker_sewing_timeout_handler(ngx_event_t *ev);

static ngx_event_t s_request_timer;

static ngx_uint_t s_request_num_wait;
static ngx_uint_t s_request_id;
static ngx_rbtree_t s_request_rbtree;

static ngx_rbtree_node_t s_request_sentinel;

static ngx_rbtree_t s_timeout_request_rbtree;
static ngx_uint_t s_timeout_request_id;
static ngx_uint_t s_timeout_num_wait;

static void request_timeout_handler(ngx_event_t *ev);

static ngx_int_t ngx_http_sewing_init_process(ngx_cycle_t *cycle);
static void ngx_http_sewing_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_sewing_handler(ngx_http_request_t *r);

static void *ngx_http_sewing_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_sewing_loc_conf_t *local_conf = NULL;
    local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_sewing_loc_conf_t));
    if (local_conf == NULL) {
        return NULL;
    }

    ngx_str_null(&local_conf->type_str);
    local_conf->type_enum = sewing_mod_type_unset;
    local_conf->sewing_crate = NULL;

    return local_conf;
}

static char *ngx_http_sewing_set_handler(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_sewing_handler;

    ngx_http_sewing_loc_conf_t *local_conf = conf;
    ngx_str_t *p_str = &local_conf->type_str;
    ngx_conf_set_str_slot(cf, cmd, conf);
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "type_str:%*s", p_str->len, p_str->data);

    extern sewing_crate_t sewing_crates[];
    extern ngx_uint_t sewing_crate_num;
    ngx_uint_t neles = sewing_crate_num;
    size_t i = 0;
    for (i = 0; i < neles; i++) {
        if (p_str->len == sewing_crates[i].type_str.len) {
            if (0 == strncmp(p_str->data, sewing_crates[i].type_str.data, p_str->len)) {
                local_conf->type_enum = sewing_crates[i].type_enum;
                local_conf->sewing_crate = &sewing_crates[i];
                break;
            }
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "sewing_set_handler done");
    return NGX_CONF_OK;
}

static ngx_command_t ngx_http_sewing_commands[] = {

    { ngx_string("sewing"),

      NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,

      ngx_http_sewing_set_handler,

      NGX_HTTP_LOC_CONF_OFFSET,

      offsetof(ngx_http_sewing_loc_conf_t, type_str),

      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_sewing_module_ctx = {
    NULL, /* preconfiguration */
    NULL, /* postconfiguration */

    NULL, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    ngx_http_sewing_create_loc_conf, /* create location configuration */
    NULL                             /* merge location configuration */
};

ngx_module_t ngx_http_sewing_module = { NGX_MODULE_V1,
                                        &ngx_http_sewing_module_ctx,  /* module context */
                                        ngx_http_sewing_commands,     /* module directives */
                                        NGX_HTTP_MODULE,              /* module type */
                                        NULL,                         /* init master */
                                        NULL,                         /* init module */
                                        ngx_http_sewing_init_process, /* init process */
                                        NULL,                         /* init thread */
                                        NULL,                         /* exit thread */
                                        ngx_http_sewing_exit_process, /* exit process */
                                        NULL,                         /* exit master */
                                        NGX_MODULE_V1_PADDING };

ngx_uint_t sewing_buff_size() {
    return 1024 * 256; // N * sizeof(ngx_uint_t)
}

ngx_uint_t sewing_pool_size(ngx_uint_t buff_num) {
    return sewing_buff_size() * buff_num;
}

static ngx_int_t ngx_http_sewing_init_process(ngx_cycle_t *cycle) {
    ngx_pool_t *pool = ngx_create_pool(sewing_pool_size(4) + 1024 * 1024 * 4, cycle->log);
    if (pool == NULL) {
        return NGX_ERROR;
    }

    int fd[2];
    int xfd, yfd;
    int r = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
    if (r < 0) {
        return NGX_ERROR;
    }
    xfd = fd[0];
    yfd = fd[1];

    worker_sewing_ctx = ngx_palloc(pool, sizeof(sewing_module_ctx_t));
    if (worker_sewing_ctx == NULL) {
        return NGX_ERROR;
    }

    worker_sewing_ctx->log = cycle->log;
    worker_sewing_ctx->write_event_handler = worker_sewing_write_handler;
    worker_sewing_ctx->read_event_handler = worker_sewing_read_handler;
    worker_sewing_ctx->timeout_event_handler = worker_sewing_timeout_handler;

    ngx_buf_t *buf = ngx_palloc(pool, sizeof(ngx_buf_t));
    ngx_uint_t buf_size = sewing_buff_size();
    buf->start = ngx_palloc(pool, buf_size);
    buf->end = buf->start + buf_size;
    buf->pos = buf->start;
    buf->last = buf->start;
    buf->memory = 1;
    worker_sewing_ctx->send_buf = buf;

    buf = ngx_palloc(pool, sizeof(ngx_buf_t));
    buf_size = sewing_buff_size();
    buf->start = ngx_palloc(pool, buf_size);
    buf->end = buf->start + buf_size;
    buf->pos = buf->start;
    buf->last = buf->start;
    buf->memory = 1;
    worker_sewing_ctx->recv_buf = buf;

    if (NGX_OK != sewing_event_add(xfd, worker_sewing_ctx)) {
        return NGX_ERROR;
    }

    sewing_work_ctx = ngx_palloc(pool, sizeof(sewing_work_ctx_t));
    if (sewing_work_ctx == NULL) {
        return NGX_ERROR;
    }
    sewing_work_ctx->xfd = xfd;
    sewing_work_ctx->yfd = yfd;

    sewing_work_ctx->flag = 1;
    sewing_work_ctx->log = cycle->log;

    buf = ngx_palloc(pool, sizeof(ngx_buf_t));
    buf_size = sewing_buff_size();
    buf->start = ngx_palloc(pool, buf_size);
    buf->end = buf->start + buf_size;
    buf->pos = buf->start;
    buf->last = buf->start;
    buf->memory = 1;
    sewing_work_ctx->send_buf = buf;

    buf = ngx_palloc(pool, sizeof(ngx_buf_t));
    buf_size = sewing_buff_size();
    buf->start = ngx_palloc(pool, buf_size);
    buf->end = buf->start + buf_size;
    buf->pos = buf->start;
    buf->last = buf->start;
    buf->memory = 1;
    sewing_work_ctx->recv_buf = buf;
    sewing_work_ctx->work_io_ctx = NULL;

    pthread_create(&sewing_work_thread, NULL, sewing_work_main, sewing_work_ctx);

    s_request_num_wait = 0;
    s_request_id = 0;
    s_timeout_request_id = 0;
    ngx_rbtree_init(&s_request_rbtree, &s_request_sentinel, ngx_rbtree_insert_value);

    s_timeout_num_wait = 0;
    ngx_rbtree_init(&s_timeout_request_rbtree, &s_request_sentinel, ngx_rbtree_insert_value);

    s_request_timer.handler = request_timeout_handler;
    s_request_timer.log = cycle->log;
    s_request_timer.data = NULL;

    // timer start
    ngx_add_timer(&s_request_timer, SEWING_REQUEST_TIMEOUT_MSEC);

    extern sewing_crate_t sewing_crates[];
    extern ngx_uint_t sewing_crate_num;
    ngx_uint_t neles = sewing_crate_num;
    size_t i = 0;
    for (i = 0; i < neles; i++) {
        ngx_int_t rc = sewing_crates[i].init();
        if (NGX_OK != rc) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0, "sewing_crate %*s init failed", sewing_crates[i].type_str.len, sewing_crates[i].type_str.data);
            return rc;
        }
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "sewing_init_process done");
    return NGX_OK;
}

static void ngx_http_sewing_exit_process(ngx_cycle_t *cycle) {
    sewing_work_ctx->flag = 0;
    pthread_join(sewing_work_thread, NULL);
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "sewing_exit_process done");
}

static ngx_inline void worker_sewing_send_request() {
    ngx_buf_t *send_buf = worker_sewing_ctx->send_buf;
    size_t buf_len = send_buf->last - send_buf->pos;
    ngx_connection_t *c = worker_sewing_ctx->c;
    ngx_event_t *wrt = c->write;
    ssize_t n;
    while (wrt->ready && 0 < buf_len) {
        n = c->send(c, send_buf->pos, buf_len);
        if (n > 0) {
            // ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "sewing_write: %*s", n, send_buf->pos);
            send_buf->pos += n;
            if (send_buf->pos == send_buf->last) {
                send_buf->pos = send_buf->start;
                send_buf->last = send_buf->start;
            }
            buf_len = send_buf->last - send_buf->pos;
        } else {
            if (n == NGX_ERROR) { // TODO ERROR
                ngx_log_error(NGX_LOG_EMERG, c->log, 0, "sewing_write failed");
            } else if (n == NGX_AGAIN) {
                if (ngx_handle_write_event(wrt, 0) != NGX_OK) {
                    ngx_log_error(NGX_LOG_EMERG, c->log, 0, "register sewing_write failed");
                }
            }
            break;
        }
    }
}

static ngx_inline void sewing_response_header(ngx_http_request_t *r, ngx_int_t rc) {
    r->headers_out.status = rc;
    r->headers_out.content_length_n = 0;
    ngx_http_send_header(r);
    ngx_http_send_special(r, NGX_HTTP_LAST);
    ngx_http_finalize_request(r, NGX_DONE);
}

static void ngx_http_sewing_handler_final(ngx_http_request_t *r) {
    if (s_request_num_wait + s_timeout_num_wait > SEWING_REQUEST_NUM_WAIT_MAX) {
        // ngx_http_finalize_request(r, NGX_HTTP_SERVICE_UNAVAILABLE);
        sewing_response_header(r, NGX_HTTP_SERVICE_UNAVAILABLE);
        return;
    }

    sewing_rbtree_node_t *p = NULL;
    size_t plen = sizeof(p);
    ngx_buf_t *send_buf = worker_sewing_ctx->send_buf;
    size_t buf_size = send_buf->end - send_buf->last;
    if (buf_size < plen) {
        // ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        sewing_response_header(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return;
    }

    s_request_num_wait++;
    s_request_id++;

    p = ngx_pcalloc(r->pool, sizeof(sewing_rbtree_node_t));
    p->node.key = s_request_id;
    p->request = r;

    p->http_status = NGX_HTTP_OK;
    p->p_content_type = NULL;
    p->p_headers = NULL;
    p->p_body = NULL;

    p->buffer.start = ngx_pcalloc(r->pool, SEWING_RESPONSE_BUFFER_SIZE);
    p->buffer.end = p->buffer.start + SEWING_RESPONSE_BUFFER_SIZE;
    p->buffer.pos = p->buffer.start;
    p->buffer.last = p->buffer.start;

    ngx_rbtree_insert(&s_request_rbtree, &(p->node));

    ngx_log_error(NGX_LOG_NOTICE, worker_sewing_ctx->log, 0, "s_request_id=%ui", s_request_id);
    ngx_log_error(NGX_LOG_NOTICE, worker_sewing_ctx->log, 0, "sewing_send: %p", p);
    send_buf->last = ngx_cpymem(send_buf->last, &p, plen);

    worker_sewing_send_request();
}

static ngx_int_t ngx_http_sewing_handler(ngx_http_request_t *r) {
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "sewing_handler is called");

    ngx_int_t rc;
    if (!(r->method & NGX_HTTP_POST)) {
        rc = ngx_http_discard_request_body(r);
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "sewing_handler return NGX_DECLINED");
        if (rc != NGX_OK) {
            return rc;
        }
        return NGX_HTTP_NOT_ALLOWED;
        // return NGX_DECLINED;
        // return NGX_HTTP_BAD_REQUEST;
        // return NGX_HTTP_FORBIDDEN;
        // return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_read_client_request_body(r, ngx_http_sewing_handler_final);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
}

static void worker_sewing_write_handler(ngx_event_t *ev) {
    ngx_connection_t *c = worker_sewing_ctx->c;
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "in worker_sewing_write_handler");
    worker_sewing_send_request();
}

static void worker_sewing_send_response(sewing_rbtree_node_t *p) {
    ngx_http_request_t *r = p->request;
    ngx_uint_t response_request_id = p->node.key;
    if (response_request_id > s_timeout_request_id) {
        ngx_rbtree_delete(&s_request_rbtree, (ngx_rbtree_node_t *)p);
        s_request_num_wait--;

        r->headers_out.status = p->http_status;
        if (NULL != p->p_content_type) {
            r->headers_out.content_type_len = p->p_content_type->len;
            r->headers_out.content_type = *(p->p_content_type);
        }
        if (NULL != p->p_headers) {
            sewing_list_table_ele_t *p_sewing_list = p->p_headers;
            while (NULL != p_sewing_list) {
                ngx_table_elt_t *table_elt = (ngx_table_elt_t *)p_sewing_list->table_elt;
                ngx_table_elt_t *new_table_elt = ngx_list_push(&r->headers_out.headers);
                *new_table_elt = *table_elt;

                p_sewing_list = (sewing_list_table_ele_t *)p_sewing_list->node.next;
            }
        }
        ngx_int_t rc = ngx_http_send_header(r);
        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "response header_only for %p", p);
            ngx_http_send_special(r, NGX_HTTP_LAST);
            ngx_http_finalize_request(r, rc);
            return;
        }
        if (NULL != p->p_body) {
            rc = ngx_http_output_filter(r, p->p_body);
        }
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "response header_body for %p", p);
        ngx_http_finalize_request(r, rc);
        return;
    }

    ngx_rbtree_node_t *p_rbtree_node = NULL;
    sewing_rbtree_node_t *p_sewing_rbtree_node = NULL;

    // use B not A
    while (s_timeout_num_wait > 0) {
        // p_rbtree_node = ngx_rbtree_min(s_timeout_request_rbtree.root, &s_request_sentinel); // A
        // p_sewing_rbtree_node = (sewing_rbtree_node_t *)p_rbtree_node; // A

        p_sewing_rbtree_node = p;               // B
        p_rbtree_node = (ngx_rbtree_node_t *)p; // B

        ngx_connection_t *c = p_sewing_rbtree_node->request->connection;

        ngx_uint_t delete_request_id = p_rbtree_node->key;
        if (delete_request_id <= response_request_id) {
            s_timeout_num_wait--;

            ngx_rbtree_delete(&s_timeout_request_rbtree, p_rbtree_node);
            // ngx_pfree(p_sewing_rbtree_node->request->pool, p_sewing_rbtree_node);

            ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "delete_request_id=%ui", delete_request_id);
            ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "delete request %p", p_rbtree_node);

            // 减少引用计数，销毁request对象
            ngx_http_finalize_request(p_sewing_rbtree_node->request, NGX_DONE);

            break; // B
        } else {
            // important
            break;
        }
    }
}

static void worker_sewing_read_handler(ngx_event_t *ev) {
    ngx_connection_t *c = worker_sewing_ctx->c;
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "in worker_sewing_read_handler");

    ngx_event_t *rev = c->read;
    ngx_buf_t *recv_buf = worker_sewing_ctx->recv_buf;

    size_t buf_size = recv_buf->end - recv_buf->last;
    ssize_t n;
    while (rev->ready && buf_size > 0) {
        n = c->recv(c, recv_buf->last, buf_size);
        if (n > 0) {
            // ngx_log_error(NGX_LOG_DEBUG, c->log, 0, "sewing_read: %*s", n, recv_buf->last);
            recv_buf->last += n;
            buf_size = recv_buf->end - recv_buf->last;
        } else {
            if (n == NGX_ERROR) {
                ngx_log_error(NGX_LOG_EMERG, c->log, 0, "sewing_read failed");
            } else if (n == NGX_AGAIN) {
                if (ngx_handle_read_event(rev, 0) != NGX_OK) {
                    ngx_log_error(NGX_LOG_EMERG, c->log, 0, "register sewing_read failed");
                }
            }
            break;
        }
    }

    sewing_rbtree_node_t *p = NULL;
    size_t plen = sizeof(p);
    size_t buf_len = recv_buf->last - recv_buf->pos;
    while (buf_len >= plen) {
        p = *((sewing_rbtree_node_t **)(recv_buf->pos));
        ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "sewing_recv: %p", p);

        recv_buf->pos += plen;
        if (recv_buf->pos == recv_buf->last) {
            recv_buf->pos = recv_buf->start;
            recv_buf->last = recv_buf->start;
        }
        buf_len = recv_buf->last - recv_buf->pos;

        worker_sewing_send_response(p);
    }
}

static void worker_sewing_timeout_handler(ngx_event_t *ev) {
    ngx_connection_t *c = worker_sewing_ctx->c;
    ngx_log_error(NGX_LOG_NOTICE, c->log, 0, "in worker_sewing_timeout_handler");
}

static void request_timeout_handler(ngx_event_t *ev) {
    ngx_log_error(NGX_LOG_NOTICE, s_request_timer.log, 0, "in request_timeout_handler");

    if (0 == s_request_num_wait) {
        ngx_add_timer(&s_request_timer, SEWING_REQUEST_TIMEOUT_MSEC);
        return;
    }

    ngx_rbtree_node_t *p = ngx_rbtree_min(s_request_rbtree.root, &s_request_sentinel);
    sewing_rbtree_node_t *p_sewing_rbtree_node = (sewing_rbtree_node_t *)p;
    ngx_http_request_t *request = p_sewing_rbtree_node->request;
    ngx_msec_t tmp_sec = ngx_time() - request->start_sec;
    while (tmp_sec >= SEWING_REQUEST_TIMEOUT_SEC) {
        s_timeout_request_id = p->key; // before delete node
        ngx_rbtree_delete(&s_request_rbtree, p);
        s_request_num_wait--;

        ngx_log_error(NGX_LOG_NOTICE, s_request_timer.log, 0, "s_timeout_request_id=%ui", s_timeout_request_id);
        p->key = s_timeout_request_id; // before insert node
        ngx_rbtree_insert(&s_timeout_request_rbtree, p);
        s_timeout_num_wait++;

        // 增加引用计数，防止sewing_work访问已销毁的request对象
        request->main->count++;

        ngx_log_error(NGX_LOG_NOTICE, s_request_timer.log, 0, "return timeout for %p", p);
        // ngx_http_finalize_request(request, NGX_HTTP_GATEWAY_TIME_OUT);
        sewing_response_header(request, NGX_HTTP_GATEWAY_TIME_OUT);

        if (0 == s_request_num_wait) {
            ngx_add_timer(&s_request_timer, SEWING_REQUEST_TIMEOUT_MSEC);
            return;
        }

        p = ngx_rbtree_min(s_request_rbtree.root, &s_request_sentinel);
        p_sewing_rbtree_node = (sewing_rbtree_node_t *)p;
        request = p_sewing_rbtree_node->request;
        tmp_sec = ngx_time() - request->start_sec;
    }

    tmp_sec = SEWING_REQUEST_TIMEOUT_SEC - tmp_sec;
    if (tmp_sec > SEWING_REQUEST_TIMEOUT_SEC) {
        tmp_sec = SEWING_REQUEST_TIMEOUT_SEC;
    }
    ngx_add_timer(&s_request_timer, tmp_sec * 1000);
}
