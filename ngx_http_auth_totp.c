#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_auth_totp.h"


static void * ngx_http_auth_totp_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_auth_totp_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_totp_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_totp_initialise(ngx_conf_t *cf);

static char * ngx_http_auth_totp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


static ngx_command_t ngx_http_auth_totp_directives[] = {

    /* For equivalence with ngx_http_auth_basic directives */
    { ngx_string("auth_totp"),  
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_http_set_complex_value_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, realm),
            NULL },

    { ngx_string("auth_totp_realm"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_http_set_complex_value_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, realm),
            NULL },

    { ngx_string("auth_totp_file"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_http_auth_totp_file,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, totp_file),
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

    return lcf;
}


static char * 
ngx_http_auth_totp_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_http_auth_totp_handler(ngx_http_request_t *r) {
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

    return NGX_CONF_OK;
}

