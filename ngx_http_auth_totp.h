#ifndef _NGX_HTTP_AUTH_TOTP_H_INCLUDED_
#define _NGX_HTTP_AUTH_TOTP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define MODULE_NAME                     ("totp")

#define NGX_HTTP_AUTH_TOTP_BUF_SIZE     (2048)


/*
    The following enumeration is intended to contain the processing states 
    employed by the configuration file parser.
*/

typedef enum {
    STATE_USER = 0,
    STATE_SECRET,
    STATE_START,
    STATE_STEP,
    STATE_LENGTH,
    STATE_SKIP
}
ngx_http_auth_totp_state_e;

typedef struct {
    ngx_rbtree_t tree;
    ngx_rbtree_node_t sentinel;
    ngx_slab_pool_t *shpool;
}
ngx_http_auth_totp_shm_t;

typedef struct {
    ngx_http_complex_value_t *realm;
    ngx_http_complex_value_t *totp_file;
    ngx_int_t length;
    ngx_int_t skew;
    time_t start;
    time_t step;
    ngx_str_t cookie;
    time_t expiry;
    ngx_flag_t reuse;
    ngx_shm_zone_t *shm;
    ngx_str_t totp_secret;
}
ngx_http_auth_totp_loc_conf_t;


#endif  /* _NGX_HTTP_AUTH_TOTP_H_INCLUDED_ */
