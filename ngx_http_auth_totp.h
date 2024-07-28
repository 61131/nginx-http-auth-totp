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
    STATE_SKIP
}
ngx_http_auth_totp_state_e;

typedef struct {
    ngx_http_complex_value_t *realm;
    ngx_http_complex_value_t *totp_file;
    ngx_int_t length;
    ngx_int_t skew;
    time_t start;
    time_t step;
}
ngx_http_auth_totp_loc_conf_t;

extern ngx_module_t ngx_http_auth_totp_module;


#endif  /* _NGX_HTTP_AUTH_TOTP_H_INCLUDED_ */
