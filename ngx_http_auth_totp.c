#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auth_totp.h"


static void * ngx_http_auth_totp_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_auth_totp_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_totp_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_totp_initialise(ngx_conf_t *cf);

static char * ngx_http_auth_totp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_auth_totp_set_realm(ngx_http_request_t *r, ngx_str_t *realm);


static ngx_command_t ngx_http_auth_totp_directives[] = {

    { ngx_string("auth_totp_file"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_http_auth_totp_file,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, totp_file),
            NULL },

    { ngx_string("auth_totp_realm"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_http_set_complex_value_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, realm),
            NULL },

    { ngx_string("auth_totp_skew"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_num_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, skew),
            NULL },

    { ngx_string("auth_totp_start"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_sec_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, start),
            NULL },

    { ngx_string("auth_totp_step"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_sec_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, step),
            NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_auth_totp_ctx = {
    NULL,                               /* preconfiguration */
    ngx_http_auth_totp_initialise,      /* postconfiguration */
    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */
    NULL,                               /* create server configuration */
    NULL,                               /* merge server configuration */
    ngx_http_auth_totp_create_loc_conf, /* create location configuration */
    ngx_http_auth_totp_merge_loc_conf   /* merge location configuration */
};

ngx_module_t ngx_http_auth_totp_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_totp_ctx,            /* module context */
    ngx_http_auth_totp_directives,      /* module directives */
    NGX_HTTP_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    NULL,                               /* exit master */
    NGX_MODULE_V1_PADDING
};


static void * 
ngx_http_auth_totp_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_totp_loc_conf_t *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_totp_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }
    lcf->realm = NGX_CONF_UNSET_PTR;
    lcf->totp_file = NGX_CONF_UNSET_PTR;
    lcf->skew = NGX_CONF_UNSET;
    lcf->start = NGX_CONF_UNSET;
    lcf->step = NGX_CONF_UNSET;

    return lcf;
}


static char * 
ngx_http_auth_totp_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    ngx_http_auth_totp_loc_conf_t *lcf = conf;
    ngx_http_compile_complex_value_t cv;
    ngx_str_t *value;

    if (lcf->totp_file != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    lcf->totp_file = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));
    if (lcf->totp_file == NULL) {
        return NGX_CONF_ERROR;
    }

    value = cf->args->elts;

    ngx_memzero(&cv, sizeof(ngx_http_compile_complex_value_t));
    cv.cf = cf;
    cv.complex_value = lcf->totp_file;
    cv.value = &value[1];
    cv.conf_prefix = 1;
    cv.zero = 1;

    if (ngx_http_compile_complex_value(&cv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_http_auth_totp_handler(ngx_http_request_t *r) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    ngx_str_t realm;
    ngx_int_t rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_totp_module);
    if ((lcf->realm == NULL) ||
            (lcf->totp_file == NULL)) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, lcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }
    if ((realm.len == 3) &&
            (ngx_strncmp(realm.data, "off", 3) == 0)) {
        return NGX_DECLINED;
    }

    /* Session handling code here */

    rc = ngx_http_auth_basic_user(r);
    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "no user/password was provided for basic authentication");
        return ngx_http_auth_totp_set_realm(r, &realm);
    }
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* File handling code here */

    return NGX_OK;
}


static ngx_int_t
ngx_http_auth_totp_initialise(ngx_conf_t *cf) {
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_auth_totp_handler;

    return NGX_OK;
}


static char * 
ngx_http_auth_totp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_auth_totp_loc_conf_t *prev = parent;
    ngx_http_auth_totp_loc_conf_t *conf = child;

    ngx_conf_merge_ptr_value(conf->realm, prev->realm, NULL);
    ngx_conf_merge_ptr_value(conf->totp_file, prev->totp_file, NULL);
    ngx_conf_merge_value(conf->skew, prev->skew, 1);
    ngx_conf_merge_sec_value(conf->start, prev->start, 0);
    ngx_conf_merge_sec_value(conf->step, prev->start, 30);

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_http_auth_totp_set_realm(ngx_http_request_t *r, ngx_str_t *realm) {
    u_char *header, *ptr;
    size_t len;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Basic realm=\"\"") - 1 + realm->len;
    header = ngx_pnalloc(r->pool, len);
    if (header == NULL) {
        r->headers_out.www_authenticate->hash = 0;
        r->headers_out.www_authenticate = NULL;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ptr = ngx_cpymem(header, "Basic realm=\"", sizeof("Basic realm=\"") - 1);
    ptr = ngx_cpymem(ptr, realm->data, realm->len);
    *ptr = '"';

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->next = NULL;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = header;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}

