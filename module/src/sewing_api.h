#ifndef _NGX_HTTP_SEWING_API_H_
#define _NGX_HTTP_SEWING_API_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "sewing.h"

#include "sewing_crate.h"

#include "sewing_work.h"

#include "sewing_task.h"

static ngx_str_t sewing_api_cntype_str = ngx_string("text/html");

static inline ngx_http_request_t *sewing_get_http_request(sewing_task_t *task) {
    sewing_rbtree_node_t *p = task->p_sewing_rbtree_node;
    return p->request;
}

static inline ngx_int_t sewing_get_thread_id(sewing_task_t *task) {
    sewing_task_ctx_t *p = task->sewing_task_ctx;
    return p->task_thread_id;
}

static inline void sewing_set_resp_status(sewing_task_t *task, ngx_int_t status) {
    sewing_rbtree_node_t *p = task->p_sewing_rbtree_node;
    p->http_status = status;
}

static inline void sewing_set_resp_cntype(sewing_task_t *task, char *resp_cntype, ngx_int_t cntype_len) {
    sewing_rbtree_node_t *p = task->p_sewing_rbtree_node;
    ngx_int_t buf_size = p->buffer.end - p->buffer.last;
    if (buf_size < sizeof(ngx_str_t) + cntype_len) {
        sewing_set_resp_status(task, NGX_HTTP_BAD_GATEWAY);
        return;
    }
    if (NULL == p->p_content_type) {
        p->p_content_type = (ngx_str_t *)p->buffer.last;
        p->buffer.last += sizeof(ngx_str_t);

        p->p_content_type->len = cntype_len;
        p->p_content_type->data = p->buffer.last;
        p->buffer.last = ngx_cpymem(p->buffer.last, resp_cntype, cntype_len);
    }
}

static inline void sewing_set_resp_body(sewing_task_t *task, char *resp_body, ngx_int_t body_len) {
    sewing_rbtree_node_t *p = task->p_sewing_rbtree_node;
    ngx_int_t buf_size = p->buffer.end - p->buffer.last;
    if (buf_size < sizeof(ngx_chain_t) + sizeof(ngx_buf_t) + body_len) {
        sewing_set_resp_status(task, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    if (NULL == p->p_content_type) {
        p->p_content_type = &sewing_api_cntype_str;
    }

    if (NULL == p->p_body) {
        p->p_body = (ngx_chain_t *)p->buffer.last;
        p->buffer.last += sizeof(ngx_chain_t);

        ngx_buf_t *b = (ngx_buf_t *)p->buffer.last;
        p->buffer.last += sizeof(ngx_buf_t);

        p->p_body->buf = b;
        p->p_body->next = NULL;

        b->pos = p->buffer.last;
        p->buffer.last = ngx_cpymem(p->buffer.last, resp_body, body_len);
        b->last = p->buffer.last;

        b->start = b->pos;
        b->end = b->last;

        b->memory = 1;
        b->last_buf = 1;
    }
}

static inline void sewing_add_resp_header(sewing_task_t *task, char *key, char *value) {
    sewing_rbtree_node_t *p = task->p_sewing_rbtree_node;
    ngx_int_t buf_size = p->buffer.end - p->buffer.last;

    ngx_int_t key_len = strlen(key);
    ngx_int_t value_len = strlen(value);
    if (buf_size < sizeof(sewing_list_table_ele_t) + sizeof(ngx_table_elt_t) + key_len + value_len) {
        sewing_set_resp_status(task, NGX_HTTP_BAD_GATEWAY);
        return;
    }

    sewing_list_table_ele_t *p_sewing_list = (sewing_list_table_ele_t *)p->buffer.last;
    p->buffer.last += sizeof(sewing_list_table_ele_t);

    p_sewing_list->node.next = (sewing_list_t *)p->p_headers;

    ngx_table_elt_t *table_elt = (ngx_table_elt_t *)p_sewing_list->table_elt;
    p->buffer.last += sizeof(ngx_table_elt_t);

    table_elt->hash = 1;

    table_elt->key.len = key_len;
    table_elt->key.data = p->buffer.last;
    p->buffer.last = ngx_cpymem(p->buffer.last, key, key_len);

    table_elt->value.len = value_len;
    table_elt->value.data = p->buffer.last;
    p->buffer.last = ngx_cpymem(p->buffer.last, value, value_len);

    p->p_headers = p_sewing_list;
}

#endif /* _NGX_HTTP_SEWING_API_H_ */
