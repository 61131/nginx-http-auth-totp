#ifndef _NGX_HTTP_AUTH_TOTP_H_INCLUDED_
#define _NGX_HTTP_AUTH_TOTP_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define MODULE_NAME     ("totp")


typedef struct {
    ngx_http_complex_value_t *realm;
    ngx_http_complex_value_t *totp_file;
}
ngx_http_auth_totp_loc_conf_t;


extern ngx_module_t ngx_http_auth_totp_module;


#endif  /* _NGX_HTTP_AUTH_TOTP_H_INCLUDED_ */
