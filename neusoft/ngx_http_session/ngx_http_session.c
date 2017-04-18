/*
 * Copyright (c) 2013 Neusoft Corperation., Ltd.
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_core_module.h>
#include <ngx_http_session.h>
#include <ngx_times.h>
#include <ngx_md5.h>

#if (NGX_HTTP_NETEYE_SECURITY)
#include <ngx_http_neteye_security.h>
#else
#error "must compile with neteye security module"
#endif

#if (NGX_HTTP_STATUS_PAGE)
#include <ngx_http_status_page.h>
#endif

static char *
ngx_http_session_number(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t
ngx_http_session_filter_init(ngx_conf_t *cf);
static void *
ngx_http_session_create_loc_conf(ngx_conf_t *cf);
static char *
ngx_http_session_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t
ngx_http_session_request_ctx_init(ngx_http_request_t *r);
static ngx_int_t
ngx_http_session_request_cleanup_init(ngx_http_request_t *r);
static ngx_int_t
__ngx_http_session_delete(ngx_http_session_t *session);
static ngx_int_t
ngx_http_session_pre_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_session_commands[] = {

    { ngx_string("session"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, enabled),
      NULL },

    { ngx_string("session_max_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_http_session_number,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("session_cookie_name"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, keyword),
      NULL },

    { ngx_string("session_timeout"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, timeout),
      NULL },

    { ngx_string("session_redirect_timeout"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, redirect_timeout),
      NULL },

    { ngx_string("session_show"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_session_conf_t, session_show_enabled),
      NULL },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_session_module_ctx = {
    ngx_http_session_pre_init,             /* preconfiguration */
    ngx_http_session_filter_init,          /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_session_create_loc_conf,       /* create location configuration */
    ngx_http_session_merge_loc_conf,        /* merge location configuration */
};


ngx_module_t  ngx_http_session_module = {
    NGX_MODULE_V1,
    &ngx_http_session_module_ctx,          /* module context */
    ngx_http_session_commands,             /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_shm_zone_t *ngx_http_session_shm_zone;
static ngx_http_session_create_ctx_t ctx_handlers[NGX_HTTP_SESSION_MAX_CTX];


static ngx_int_t
ngx_http_session_pre_init(ngx_conf_t *cf)
{
    memset(ctx_handlers, 0, sizeof(ngx_http_session_create_ctx_t)
            * NGX_HTTP_SESSION_MAX_CTX);

    return NGX_OK;
}

static ngx_int_t
ngx_http_session_gen_sid(ngx_http_request_t *r, ngx_str_t *sid)
{
    ngx_md5_t                        md5_state;
    u_char                           md5_digest[16];
    u_char                           hex_output[16 * 2 + 1], source[512];
    ngx_uint_t                       di, source_len = 0, port_time_len;
    struct sockaddr_in               *peer_addr;
    socklen_t                        peer_len = NGX_SOCKADDRLEN;
    u_char                           sa[NGX_SOCKADDRLEN];
    ngx_int_t                        ret = 0;
    ngx_time_t                       *time;

    memset(source, 0, 512);

    memcpy(source, r->connection->addr_text.data, r->connection->addr_text.len);
    source_len += r->connection->addr_text.len;

    ret = getpeername(r->connection->fd, (struct sockaddr *)&sa, &peer_len);
    if (ret < 0) {
        return NGX_ERROR;
    }

    time = ngx_timeofday();
    if (!time) {
        return NGX_ERROR;
    }

    peer_addr = (struct sockaddr_in *)sa;
    port_time_len = sprintf((char *)source + source_len, ":%d %d.%d",
            peer_addr->sin_port, (int)ngx_time(), (int)time->msec);

    if (port_time_len <= 0) {
        return NGX_ERROR;
    }

    source_len += port_time_len;

    ngx_md5_init(&md5_state);
    ngx_md5_update(&md5_state, (void *)source, source_len);
    ngx_md5_final(md5_digest, &md5_state);

    for (di = 0; di < 16; di++) {
        sprintf((char *)hex_output + di * 2, "%02x", md5_digest[di]);
    }

    memcpy(sid->data, hex_output, NGX_HTTP_SESSION_DEFAULT_SID_LEN);
    sid->data[NGX_HTTP_SESSION_DEFAULT_SID_LEN] = 0;
    sid->len = NGX_HTTP_SESSION_DEFAULT_SID_LEN;

    return NGX_OK;
}


static ngx_int_t
ngx_http_session_cookie_hash(ngx_http_request_t *r, ngx_str_t *cookie)
{
    unsigned long h = 0, g, ha;
    ngx_http_core_srv_conf_t *cscf;
    u_char *k;
    ngx_uint_t len;

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    len = cookie->len + cscf->virtual_server_name.len;

    k = ngx_pcalloc(r->pool, len);
    if (!k) {
        return 0;
    }

    memcpy(k, cookie->data, cookie->len);
    memcpy(k + cookie->len, cscf->virtual_server_name.data,
            cscf->virtual_server_name.len);

    while (len) {
        h = (h << 4) + *k++;
        g = h & 0xf0000000l;
        if (g) h ^= g >> 24;
        h &= ~g;

        len--;
    }

    ha = h % NGX_HTTP_SESSION_DEFAULT_NUMBER;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "session hash: %u\n", ha);

    return ha;
}


static ngx_http_session_t *
__ngx_http_session_search(ngx_http_request_t *r, ngx_str_t *cookie)
{
    ngx_http_session_list_t          *session_list;
    ngx_http_session_t               *tmp;
    ngx_int_t                        hash;

    session_list = ngx_http_session_shm_zone->data;

    hash = ngx_http_session_cookie_hash(r, cookie);

    tmp = session_list->sessions[hash];
    if (!tmp) {
        return NULL;
    }

    while (tmp) {
        if (!memcmp(tmp->id, cookie->data, cookie->len)
                && tmp->des == 0) {
            ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "session search ok, id: %s, addr: %p\n", tmp->id, tmp);
            return tmp;
        }

        tmp = tmp->next;
    }

    return NULL;
}


static ngx_int_t
__ngx_http_session_get_ref(ngx_http_request_t *r)
{
    ngx_http_session_t *session;

    session = ngx_http_session_get_request_session(r);
    session->ref++;

    return NGX_OK;
}


static ngx_int_t
ngx_http_session_insert(ngx_http_request_t *r, ngx_str_t *cookie)
{
    ngx_http_session_list_t          *session_list;
    ngx_http_session_t               *session, *tmp;
    ngx_int_t                        hash;
    ngx_http_session_conf_t         *sscf;
    u_char                           file[64];
    ngx_int_t                        i;

    sscf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    session_list = ngx_http_session_shm_zone->data;

    ngx_shmtx_lock(&session_list->shpool->mutex);

    session = ngx_slab_alloc_locked(session_list->shpool,
            sizeof(ngx_http_session_t));
    if (session == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                "slab alloc failed");

        ngx_shmtx_unlock(&session_list->shpool->mutex);
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
        "session create: %p\n", session);

    memset(session, 0, sizeof(ngx_http_session_t));
    memcpy(session->id, cookie->data, cookie->len);

    /* hang session to hash table */
    hash = ngx_http_session_cookie_hash(r, cookie);

    if (session_list->sessions[hash]) {
        tmp = session_list->sessions[hash];

        while (tmp->next) {
            tmp = tmp->next;
        }

        tmp->next = session;
        session->prev = tmp;
        session->next = NULL;
    } else {
        session_list->sessions[hash] = session;
        session->next = NULL;
        session->prev = NULL;
        session->slot = (void **)(&(session_list->sessions[hash]));
    }

    memset(file, 0, 64);
    sprintf((char *)file, "/var/tmp/%s", session->id);

    if (ngx_shmtx_create(&session->mutex, (void *)&session->lock,
                file) != NGX_OK) {
        ngx_shmtx_unlock(&session_list->shpool->mutex);
        ngx_slab_free_locked(session_list->shpool, session);
        return NGX_ERROR;
    }

    session->ter_time = ngx_time() + sscf->redirect_timeout;
    ngx_http_session_set_request_session(r, session);
    __ngx_http_session_get_ref(r);

    /* Initial ctx for other module use */
    if (session->good == 0) {
        session->good = 1;
        for (i = 0; i < NGX_HTTP_SESSION_MAX_CTX; i++) {
            if (ctx_handlers[i]) {
                ctx_handlers[i](session);
            }
        }
    }

    ngx_shmtx_unlock(&session_list->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
__ngx_http_session_ctx_delete(ngx_http_session_t *session)
{
    ngx_int_t i;
    ngx_http_session_ctx_t *ctx;

    ctx = session->ctx;

    for (i = 0; i < NGX_HTTP_SESSION_MAX_CTX; i++) {
        if (ctx[i].in_use) {
            if (ctx[i].data && ctx[i].destroy) {
                ctx[i].destroy(&ctx[i]);
            } else {
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}


static ngx_int_t
__ngx_http_session_delete(ngx_http_session_t *session)
{
    ngx_int_t ret;
    ngx_http_session_list_t          *session_list;

    session_list = ngx_http_session_shm_zone->data;

    if (!session->ref) {
        if (!session->next && !session->prev) {
            /* the only node in the chain */
            *(session->slot) = NULL;
        } else if (!session->prev && session->next) {
            /* first node in the chain */
            *(session->slot) = session->next;
            ((ngx_http_session_t *)(session->next))->prev = NULL;
            ((ngx_http_session_t *)(session->next))->slot = session->slot;
        } else if (session->next && session->prev) {
            /* node in the middle */
            ((ngx_http_session_t *)(session->prev))->next = session->next;
            ((ngx_http_session_t *)(session->next))->prev = session->prev;
        } else if (session->prev && !session->next) {
            /* last node in the chain */
            ((ngx_http_session_t *)(session->prev))->next = NULL;
        }

        session->next = session->prev = NULL;

        __ngx_http_session_ctx_delete(session);
        ngx_shmtx_destroy(&session->mutex);

        ngx_slab_free_locked(session_list->shpool, session);
        ret = NGX_OK;
    } else {
        ret = NGX_ERROR;
    }

    return ret;
}


ngx_int_t
ngx_http_session_delete(ngx_http_request_t *r)
{
    ngx_http_session_list_t          *session_list;
    ngx_http_session_t               *session, *old;
    ngx_str_t                        cookie;

    old = ngx_http_session_get_request_session(r);
    if (old == NULL)
        return NGX_ERROR;

    cookie.data = (u_char*)old->id;
    cookie.len = strlen(old->id);

    session_list = ngx_http_session_shm_zone->data;

    ngx_shmtx_lock(&session_list->shpool->mutex);

    session = __ngx_http_session_search(r, &cookie);
    if (!session) {
        ngx_shmtx_unlock(&session_list->shpool->mutex);
        return NGX_ERROR;
    }

    /* found a session */
    if (!session->ref) {
        __ngx_http_session_delete(session);

        ngx_http_session_clr_request_session(r);
    } else {
        old->des = 1;
    }

    ngx_shmtx_unlock(&session_list->shpool->mutex);

    return NGX_OK;
}


static ngx_int_t
__ngx_http_session_put_ref(ngx_http_request_t *r)
{
    ngx_http_session_t *session;

    session = ngx_http_session_get_request_session(r);
    session->ref--;

    if (session->ref == 0)
        ngx_http_session_clr_request_session(r);

    return NGX_OK;
}


static ngx_int_t
ngx_http_session_is_favico(ngx_http_request_t *r)
{
    char *favico = "/favicon.ico";
    ngx_uint_t len = strlen(favico);

    if (r->uri.len != len)
        return 0;

    if (!memcmp(favico, (char *)r->uri.data, len))
        return 1;

    return 0;
}


static ngx_int_t
ngx_http_session_handler(ngx_http_request_t *r)
{
    ngx_http_session_conf_t             *sscf;
    ngx_http_session_t                  *session;
    ngx_http_session_list_t             *session_list;
    ngx_str_t                           sid;
    ngx_str_t                           cookie;
    ngx_int_t                           ret;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "session handler begin");

    sscf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    if (!sscf->enabled) {
        return NGX_DECLINED;
    }

    if (ngx_http_session_request_cleanup_init(r) == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (sscf->session_show_enabled
            || ngx_http_session_is_favico(r)) {
        ngx_http_session_set_bypass(r);
        ngx_http_session_clr_found(r);

        return NGX_DECLINED;
    }

    memset(&cookie, 0, sizeof(ngx_str_t));

    ret = ngx_http_parse_multi_header_lines(&r->headers_in.cookies,
            &sscf->keyword, &cookie);

    session_list = ngx_http_session_shm_zone->data;

    if (ret == NGX_DECLINED || cookie.len == 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "new session, create one when response");
        goto create_session;
    }

    session = __ngx_http_session_search(r, &cookie);
    if (!session) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "session time out!");
        ngx_shmtx_unlock(&session_list->shpool->mutex);
create_session:
        ngx_http_session_clr_found(r);

        memset(&sid, 0, sizeof(ngx_str_t));

        sid.data = ngx_pcalloc(r->pool, 33);
        if (sid.data == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ret = ngx_http_session_gen_sid(r, &sid);
        if (ret != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ret = ngx_http_session_insert(r, &sid);
        if (ret != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    } else {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                "find a session");

        ngx_http_session_set_found(r);

        ngx_http_session_set_request_session(r, session);
        __ngx_http_session_get_ref(r);

        /* reset timer */
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "session: %p, ter_time: %d, ref: %d, good: %d\n",
            session, session->ter_time, session->ref, session->good);

        session->ter_time = ngx_time() + sscf->timeout;

        ngx_shmtx_unlock(&session_list->shpool->mutex);
    }

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_session_header_filter(ngx_http_request_t *r)
{
    ngx_http_session_conf_t      *sscf;
    ngx_uint_t                       status;
    ngx_http_upstream_t              *u;
    ngx_table_elt_t                  *set_cookie;
    u_char                           *cookie;
    ngx_http_session_t               *session;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "session filter begin\n");

    sscf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    if (!sscf->enabled) {
        return NGX_DECLINED;
    }

    if (ngx_http_session_test_bypass(r)) {
        return NGX_DECLINED;
    }

    if (ngx_http_session_test_found(r)) {
        return NGX_DECLINED;
    }

    /* r->session_create is set, create a new session */
    u = r->upstream;
    if (!u && !ngx_http_session_test_local(r)) {
        return NGX_DECLINED;
    }

    if (u) {
        status = u->state->status;

        if (status < 200 || status > 400) {
            return NGX_DECLINED;
        }
    }

    session = ngx_http_session_get(r);
    if (session == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cookie = ngx_pcalloc(r->pool, (strlen((char *)sscf->keyword.data) + 2 +
                NGX_HTTP_SESSION_DEFAULT_SID_LEN +
                strlen("; Path=/; HttpOnly")));
    if (cookie == NULL) {
        ngx_http_session_put(r);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_sprintf(cookie, "%s=%s; Path=/; HttpOnly",
            sscf->keyword.data, session->id);

    ngx_http_session_put(r);

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    set_cookie->hash = 1;
    set_cookie->key.len = sizeof ("Set-Cookie") - 1;
    set_cookie->key.data = (u_char *) "Set-Cookie";
    set_cookie->value.len = ngx_strlen(cookie);
    set_cookie->value.data = cookie;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "filter end\n");

    return NGX_DECLINED;
}


static ngx_int_t
ngx_http_session_filter_init(ngx_conf_t *cf)
{
    ngx_int_t                           ret;

    ret = ngx_http_neteye_security_ctx_register(NGX_HTTP_NETEYE_SESSION,
            ngx_http_session_request_ctx_init);

    if (ret != NGX_OK) {
        return ret;
    }

    ret = ngx_http_neteye_security_header_register(
            NGX_HTTP_NETEYE_SESSION, ngx_http_session_header_filter);

    if (ret != NGX_OK) {
        return ret;
    }

    return ngx_http_neteye_security_request_register(NGX_HTTP_NETEYE_SESSION,
            ngx_http_session_handler);
}


static ngx_int_t
ngx_http_session_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t                *shpool;
    ngx_http_session_list_t        *session_list;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    session_list = ngx_slab_alloc(shpool, sizeof(ngx_http_session_list_t));
    if (session_list == NULL) {
        return NGX_ERROR;
    }

    memset(session_list, 0, sizeof(ngx_http_session_list_t));

    session_list->log = ngx_slab_alloc(shpool, sizeof(ngx_log_t));
    if (session_list->log == NULL) {
        return NGX_ERROR;
    }

    session_list->log->file = ngx_slab_alloc(shpool, sizeof(ngx_open_file_t));
    if (session_list->log->file == NULL) {
        return NGX_ERROR;
    }

    session_list->log->file->fd = NGX_INVALID_FILE;

    session_list->shpool = shpool;

    shm_zone->data = session_list;

    return NGX_OK;
}


static ngx_int_t
ngx_http_session_manager(void)
{
    ngx_http_session_t             *session;
    ngx_http_session_t             *next;
    ngx_http_session_list_t        *session_list;
    ngx_uint_t                     i;

    session_list = ngx_http_session_shm_zone->data;

    ngx_shmtx_lock(&session_list->shpool->mutex);

    for (i = 0; i < NGX_HTTP_SESSION_DEFAULT_NUMBER; i++) {
        session = session_list->sessions[i];
        while (session) {
            next = session->next;

            if (session->ter_time <= ngx_time()) {
                if (session->ref == 0) {
                    __ngx_http_session_delete(session);
                } else {
                    session->des = 1;
                }
            }

            session = next;
        }
    }

    ngx_shmtx_unlock(&session_list->shpool->mutex);

    return NGX_OK;
}


static char *
ngx_http_session_number(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                       *value;
    ngx_str_t                       *shm_name;
    ngx_int_t                       shm_size;
    ngx_int_t                       number;

    value = cf->args->elts;
    number = ngx_atoi(value[1].data, value[1].len);
    if (number <= 0) {
        return "session number must large than 0";
    }

    shm_name = ngx_palloc(cf->pool, sizeof(*shm_name));
    shm_name->len = sizeof("session");
    shm_name->data = (unsigned char *) "session";

    shm_size = (sizeof(ngx_http_session_t) +
            NGX_HTTP_SESSION_CTX_SIZE) * number +
            sizeof(ngx_http_session_list_t);
    ngx_http_session_shm_zone = ngx_shared_memory_add(
            cf, shm_name, shm_size,
            &ngx_http_session_module);

    if (ngx_http_session_shm_zone == NULL) {
        return "init shared memory failed";
    }

    ngx_http_session_shm_zone->init = ngx_http_session_init_shm_zone;

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_session_show_handler(ngx_http_request_t *r)
{
    ngx_int_t                        rc, j = 0;
    ngx_buf_t                        *b;
    ngx_chain_t                      out;
    ngx_str_t                        *test;
    ngx_uint_t                       i;
    ngx_http_session_list_t          *session_list;
    ngx_http_session_t               *tmp;
    ngx_http_session_conf_t      *sscf;
    const char                       *banner =
        "Session mechanism is not enabled on this v-server<br>";

    ngx_http_session_set_bypass(r);

    sscf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    test = ngx_pcalloc(r->pool, sizeof(ngx_str_t));
    if (!test) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    test->data = ngx_pcalloc(r->pool,
            NGX_HTTP_SESSION_DEFAULT_NUMBER * sizeof(ngx_http_session_t)
            + 1024);
    if (!test->data) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (!sscf->enabled) {
        memcpy(test->data, banner, strlen(banner));
        test->len = strlen(banner);

        goto not_enabled;
    } else {
        memcpy(test->data, "Session(s): <br>", strlen("Session(s): <br>"));
        test->len = strlen("Session(s): <br>");
    }

    session_list = ngx_http_session_shm_zone->data;
    ngx_shmtx_lock(&session_list->shpool->mutex);

    for (i = 0; i < NGX_HTTP_SESSION_DEFAULT_NUMBER; i++) {
        tmp = session_list->sessions[i];
        if (!tmp) {
            continue;
        }

        while (tmp) {
            j = sprintf((char *)(test->data + test->len),
                    "id: %s, timeout: %d, des: %d, ref: %d <br>",
                    tmp->id, (int)(tmp->ter_time - ngx_time()),
                    tmp->des, tmp->ref);

            test->len += j;

            tmp = tmp->next;
        }
    }

    ngx_shmtx_unlock(&session_list->shpool->mutex);

    if (test->len == strlen("Session(s): <br>")) {
        memcpy(test->data + strlen("Session(s): <br>"), "No session<br>", 14);
        test->len += 14;
    }

not_enabled:
    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "Failed to allocate response buffer.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    b->pos = test->data;
    b->last = test->data + test->len;

    b->memory = 1;
    b->last_buf = 1;

    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = test->len;

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    return ngx_http_output_filter(r, &out);
}


static void *
ngx_http_session_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_session_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_session_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enabled = NGX_CONF_UNSET;
    conf->timeout = NGX_CONF_UNSET;
    conf->redirect_timeout = NGX_CONF_UNSET;
    conf->session_show_enabled = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_session_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_session_conf_t  *prev = parent;
    ngx_http_session_conf_t  *conf = child;
    ngx_http_core_loc_conf_t *clcf;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    if (conf->enabled) {
        if (ngx_http_session_shm_zone == NULL) {
            return "no session_max_size is set";
        }

        cf->cycle->session_callback = ngx_http_session_manager;
        cf->cycle->session_enabled = 1;
    }

    ngx_conf_merge_value(conf->timeout, prev->timeout,
            NGX_HTTP_SESSION_DEFAULT_TMOUT);
    ngx_conf_merge_value(conf->redirect_timeout, prev->redirect_timeout,
            NGX_HTTP_SESSION_DEFAULT_REDIRECT_TMOUT);
    ngx_conf_merge_str_value(conf->keyword, prev->keyword,
            NGX_HTTP_SESSION_DEFAULT_COOKIE);

    if (conf->redirect_timeout > conf->timeout) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                "redirect timeout is %d, timeout is %d\n",
                (int)conf->redirect_timeout, (int)conf->timeout);
        return "redirect timeout must not be larger than session timeout";
    }

    ngx_conf_merge_value(conf->session_show_enabled,
            prev->session_show_enabled, 0);
    if (conf->session_show_enabled) {
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
        clcf->handler = ngx_http_session_show_handler;
    }

    return NGX_CONF_OK;
}


void * ngx_http_session_shm_alloc(size_t size)
{
    ngx_http_session_list_t          *session_list;
    void                             *p;

    session_list = ngx_http_session_shm_zone->data;

    ngx_shmtx_lock(&session_list->shpool->mutex);

    p = ngx_slab_alloc_locked(session_list->shpool, size);

    ngx_shmtx_unlock(&session_list->shpool->mutex);

    return p;
}

void ngx_http_session_shm_free(void *p)
{
    ngx_http_session_list_t          *session_list;

    session_list = ngx_http_session_shm_zone->data;

    ngx_shmtx_lock(&session_list->shpool->mutex);

    ngx_slab_free_locked(session_list->shpool, p);

    ngx_shmtx_unlock(&session_list->shpool->mutex);

    return;
}


void * ngx_http_session_shm_alloc_nolock(size_t size)
{
    void                             *p;
    ngx_http_session_list_t          *session_list;

    session_list = ngx_http_session_shm_zone->data;

    p = ngx_slab_alloc_locked(session_list->shpool, size);

    return p;
}


void ngx_http_session_shm_free_nolock(void *p)
{
    ngx_http_session_list_t          *session_list;

    session_list = ngx_http_session_shm_zone->data;

    ngx_slab_free_locked(session_list->shpool, p);

    return;
}


ngx_http_session_ctx_t *
ngx_http_session_find_ctx(ngx_http_session_t *session, u_char *name)
{
    ngx_int_t                        i, found = -1;
    ngx_http_session_ctx_t           *ctx;

    ctx = session->ctx;

    for (i = 0; i < NGX_HTTP_SESSION_MAX_CTX; i++) {
        if (ctx[i].in_use == 1
                && !strcmp((char *)(ctx[i].name), (char *)name)) {
            /* find a ctx */
            found = i;

            return &ctx[found];
        }
    }

    return NULL;
}


/*
 * no lock in this function must lock before use
 */
ngx_http_session_ctx_t *
ngx_http_session_create_ctx(ngx_http_session_t *session, u_char *name,
        ngx_int_t (*init)(void *ctx), void (*destroy)(void *ctx))
{
    ngx_int_t                        i;
    ngx_http_session_ctx_t           *ctx;

    ctx = ngx_http_session_find_ctx(session, name);
    if (ctx) {
        return NULL;
    }

    /* create a new ctx */

    if (name == NULL || init == NULL || destroy == NULL) {
        return NULL;
    }

    ctx = session->ctx;

    for (i = 0; i < NGX_HTTP_SESSION_MAX_CTX; i++) {
        if (ctx[i].in_use == 0) {
            /* find a empty slot */
            if (init(&ctx[i]) != NGX_OK) {
                return NULL;
            }

            ctx[i].destroy = destroy;

            ctx[i].in_use = 1;
            strncpy((char *)(ctx[i].name), (char *)name,
                    NGX_HTTP_SESSION_CTX_NAME_LEN);

            return &ctx[i];
        }
    }

    /* slots full */

    return NULL;

}


void
ngx_http_session_destroy_ctx(ngx_http_session_t *session, u_char *name)
{
    ngx_http_session_ctx_t *ctx;

    ctx = ngx_http_session_find_ctx(session, name);
    if (ctx == NULL)
        return;

    if (ctx->data) {
        if (ctx->destroy) {
            ctx->destroy(ctx);
            memset(ctx, 0, sizeof(ngx_http_session_ctx_t));
        } else {
            /* have data but no destroy function */
            fprintf(stderr,
                    "ERROR: no destroyer in session ctx(%s), memory leaks...\n",
                    ctx->name);
        }
    }

    return;
}


ngx_http_session_t *
ngx_http_session_get(ngx_http_request_t *r)
{
    ngx_http_session_list_t *session_list;
    ngx_http_session_t      *session;
    ngx_http_session_conf_t      *sscf;

    sscf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    if (!sscf->enabled) {
        return NULL;
    }

    session_list = ngx_http_session_shm_zone->data;

    ngx_shmtx_lock(&session_list->shpool->mutex);

    session = ngx_http_session_get_request_session(r);
    if (!session)
        goto out;

    __ngx_http_session_get_ref(r);

out:
    ngx_shmtx_unlock(&session_list->shpool->mutex);

    return session;
}

void ngx_http_session_put(ngx_http_request_t *r)
{
    ngx_http_session_list_t *session_list;
    ngx_http_session_t      *session;
    ngx_http_session_conf_t      *sscf;

    sscf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);

    if (!sscf->enabled) {
        return;
    }

    session_list = ngx_http_session_shm_zone->data;

    ngx_shmtx_lock(&session_list->shpool->mutex);

    session = ngx_http_session_get_request_session(r);
    if (!session)
        goto out;

    __ngx_http_session_put_ref(r);

out:
    ngx_shmtx_unlock(&session_list->shpool->mutex);

    return;
}


static ngx_http_session_request_ctx_t *
ngx_http_session_get_request_ctx(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_ns_get_module_ctx(r, ngx_http_session_module);

    return ctx;
}

void ngx_http_session_set_found(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->found = 1;
}


void ngx_http_session_set_bypass(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->bypass = 1;
}


void ngx_http_session_set_local(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->local = 1;
}


void ngx_http_session_clr_found(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->found = 0;
}


void ngx_http_session_clr_bypass(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->bypass = 0;
}


void ngx_http_session_clr_local(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->local = 0;
}


ngx_uint_t
ngx_http_session_test_found(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->found;
}


ngx_uint_t
ngx_http_session_test_bypass(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->bypass;
}


ngx_uint_t
ngx_http_session_test_local(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return 0;

    return ctx->local;
}


void
ngx_http_session_set_request_session(ngx_http_request_t *r,
        ngx_http_session_t *session)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    ctx->session = session;
}


ngx_http_session_t *
ngx_http_session_get_request_session(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return NULL;

    return ctx->session;
}


void
ngx_http_session_clr_request_session(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t       *ctx;

    ctx = ngx_http_session_get_request_ctx(r);
    if (ctx == NULL)
        return;

    /* ctx->session = NULL; */
}


static ngx_int_t
ngx_http_session_request_ctx_init(ngx_http_request_t *r)
{
    ngx_http_session_request_ctx_t    *ctx;

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_session_request_ctx_t));
    if (ctx == NULL)
        return NGX_ERROR;

    ngx_http_ns_set_ctx(r, ctx, ngx_http_session_module);

    return NGX_OK;
}


static void
ngx_http_session_cleanup(void *data)
{
    ngx_http_request_t      *r = data;

    if (ngx_http_session_get_request_session(r)) {
        ngx_http_session_put(r);
    }
}


static ngx_int_t
ngx_http_session_request_cleanup_init(ngx_http_request_t *r)
{
    ngx_http_cleanup_t             *cln;

    cln = ngx_http_cleanup_add(r, 0);
    if (cln == NULL) {
        return NGX_ERROR;
    }

    cln->handler = ngx_http_session_cleanup;
    cln->data = r;

    return NGX_OK;
}


ngx_int_t
ngx_http_session_is_enabled(ngx_http_request_t *r)
{
    ngx_http_session_conf_t       *sscf;

    sscf = ngx_http_get_module_loc_conf(r, ngx_http_session_module);
    if (!sscf->enabled) {
        return 0;
    }

    return 1;
}


void ngx_http_session_register_create_ctx_handler(
        ngx_http_session_create_ctx_t handler)
{
    ngx_int_t                      i;

    for (i = 0; i < NGX_HTTP_SESSION_MAX_CTX; i++) {
        if (!ctx_handlers[i]) {
            ctx_handlers[i] = handler;
            return;
        }
    }
}
