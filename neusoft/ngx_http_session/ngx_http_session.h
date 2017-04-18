/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */
#ifndef _NGX_HTTP_SESSION_H_INCLUDED_
#define _NGX_HTTP_SESSION_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_SESSION_DEFAULT_TMOUT              60      //second
#define NGX_HTTP_SESSION_DEFAULT_REDIRECT_TMOUT     5       //second
#define NGX_HTTP_SESSION_DEFAULT_NUMBER             50000
#define NGX_HTTP_SESSION_DEFAULT_COOKIE             "SENGINX-SESSION-ID"
#define NGX_HTTP_SESSION_CTX_SIZE                   512
#define NGX_HTTP_SESSION_MAX_CTX                    32
#define NGX_HTTP_SESSION_CTX_NAME_LEN               32
#define MD5_LEN                                     32
#define NGX_HTTP_SESSION_DEFAULT_SID_LEN            MD5_LEN

typedef struct {
    ngx_int_t in_use;
    u_char name[NGX_HTTP_SESSION_CTX_NAME_LEN];

    void *data;
    void (*destroy)(void *ctx);

    ngx_shmtx_t       mutex;
    ngx_atomic_t      lock;
} ngx_http_session_ctx_t;

typedef struct {
    u_char     found:1;
    u_char     bypass:1;
    u_char     local:1;
    void      *session;
} ngx_http_session_request_ctx_t;

typedef ngx_int_t (*ngx_http_session_init_ctx_t)(void *ctx);
typedef void (*ngx_http_session_destroy_ctx_t)(void *data);

typedef struct {
    /* session id */
    char                    id[NGX_HTTP_SESSION_DEFAULT_SID_LEN];
    void                    *next;
    void                    *prev;

    void                    **slot;         /* point to sessions list,
                                               only the first node has this */
    int                     ref;            /* ref count */
    int                     des:1;          /* should be destroyed or not */
    int                     good:1;         /* on the new session chain */

    time_t                  ter_time;        /* time te be terminated */

    /* store other modules' ctx */
    ngx_http_session_ctx_t  ctx[NGX_HTTP_SESSION_MAX_CTX];
    ngx_shmtx_t             mutex;
    ngx_atomic_t            lock;
} ngx_http_session_t;

typedef void (*ngx_http_session_create_ctx_t)(ngx_http_session_t *);

typedef struct {
    ngx_slab_pool_t        *shpool;
    ngx_log_t              *log;

    /* the hash table */
    ngx_http_session_t     *sessions[NGX_HTTP_SESSION_DEFAULT_NUMBER];
} ngx_http_session_list_t;

typedef struct {
    ngx_flag_t              enabled;
    ngx_int_t               timeout;  /* in seconds */
    ngx_int_t               redirect_timeout;  /* in seconds */
    ngx_str_t               keyword;
    ngx_flag_t              session_show_enabled;
} ngx_http_session_conf_t;

/* APIs */
void ngx_http_session_register_create_ctx_handler(
        ngx_http_session_create_ctx_t handler);

ngx_int_t
ngx_http_session_delete(ngx_http_request_t *r);

void * ngx_http_session_shm_alloc(size_t size);
void ngx_http_session_shm_free(void *);

void * ngx_http_session_shm_alloc_nolock(size_t size);
void ngx_http_session_shm_free_nolock(void *);

ngx_http_session_ctx_t *
ngx_http_session_create_ctx(ngx_http_session_t *session, u_char *name,
        ngx_int_t (*init)(void *ctx), void (*destroy)(void *data));

ngx_http_session_ctx_t *
ngx_http_session_find_ctx(ngx_http_session_t *session, u_char *name);

void
ngx_http_session_destroy_ctx(ngx_http_session_t *session, u_char *name);

ngx_http_session_t * ngx_http_session_get(ngx_http_request_t *r);
void ngx_http_session_put(ngx_http_request_t *r);


void
ngx_http_session_set_request_session(ngx_http_request_t *r,
        ngx_http_session_t *session);
ngx_http_session_t *
ngx_http_session_get_request_session(ngx_http_request_t *r);
void
ngx_http_session_clr_request_session(ngx_http_request_t *r);

void ngx_http_session_set_found(ngx_http_request_t *r);
void ngx_http_session_set_create(ngx_http_request_t *r);
void ngx_http_session_set_bypass(ngx_http_request_t *r);
void ngx_http_session_set_local(ngx_http_request_t *r);

void ngx_http_session_clr_found(ngx_http_request_t *r);
void ngx_http_session_clr_create(ngx_http_request_t *r);
void ngx_http_session_clr_bypass(ngx_http_request_t *r);
void ngx_http_session_clr_local(ngx_http_request_t *r);

ngx_uint_t ngx_http_session_test_found(ngx_http_request_t *r);
ngx_uint_t ngx_http_session_test_bypass(ngx_http_request_t *r);
ngx_uint_t ngx_http_session_test_local(ngx_http_request_t *r);

ngx_int_t
ngx_http_session_is_enabled(ngx_http_request_t *r);

#endif
