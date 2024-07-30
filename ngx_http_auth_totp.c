#include <stdint.h>
#include <time.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <openssl/hmac.h>

#include "ngx_http_auth_totp.h"


static uint32_t ngx_http_auth_totp_algorithm_hotp(u_char *key, size_t length, uint64_t count, size_t digits);

static void * ngx_http_auth_totp_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_auth_totp_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_totp_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_totp_initialise(ngx_conf_t *cf);

static char * ngx_http_auth_totp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_auth_totp_set_cookie(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_totp_set_realm(ngx_http_request_t *r, ngx_str_t *realm);

static ngx_int_t ngx_http_auth_totp_validation(ngx_http_request_t *r, ngx_str_t *realm, u_char *key, size_t length, time_t start, time_t step, size_t digits);


static ngx_int_t powi[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };


static ngx_command_t ngx_http_auth_totp_directives[] = {

    { ngx_string("auth_totp_cookie"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_str_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, cookie),
            NULL },

    { ngx_string("auth_totp_expiry"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_sec_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, expiry),
            NULL },

    { ngx_string("auth_totp_file"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_http_auth_totp_file,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, totp_file),
            NULL },

    { ngx_string("auth_totp_length"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_num_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, length),
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


static uint32_t 
ngx_http_auth_totp_algorithm_hotp(u_char *key, size_t length, uint64_t count, size_t digits) {
    uint64_t value;
    uint32_t bin;
    uint8_t buffer[8], offset, *result;
    int index;

    /*
        This function implements the hash-based one-time password (HTOP) algorithm 
        as defined in RFC 4226, which serves as the base of the time-based one-time 
        password (TOTP) algorithm defined in RFC 6238.
    */

    //  Step 1: Generate HMAC-SHA-1 value
    for (value = count, index = 7; index >= 0; index--) {
        buffer[index] = (uint8_t)(value & 0xff);
        value >>= 8;
    }
    result = HMAC(EVP_sha1(), key, length, (const unsigned char *)buffer, sizeof(buffer), NULL, 0);
    //  Step 2: Generate four-byte string (dynamic truncation)
    offset = result[19] & 0x0f;
    bin = ((result[offset] & 0x7f) << 24) |
            ((result[offset + 1] & 0xff) << 16) |
            ((result[offset + 2] & 0xff) << 8) |
            (result[offset + 3] & 0xff);
    //  Step 3: Compute HOTP value
    return (bin % powi[digits]);
}


static void * 
ngx_http_auth_totp_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_auth_totp_loc_conf_t *lcf;

    lcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_totp_loc_conf_t));
    if (lcf == NULL) {
        return NULL;
    }
    lcf->realm = NGX_CONF_UNSET_PTR;
    lcf->totp_file = NGX_CONF_UNSET_PTR;
    lcf->length = NGX_CONF_UNSET;
    lcf->skew = NGX_CONF_UNSET;
    lcf->start = NGX_CONF_UNSET;
    lcf->step = NGX_CONF_UNSET;
    /* lcf->cookie = { 0, NULL }; */
    lcf->expiry = NGX_CONF_UNSET;

    return lcf;
}


static ngx_int_t 
ngx_http_auth_totp_get_cookie(ngx_http_request_t *r) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    ngx_table_elt_t *cookie;
    ngx_str_t value;
    uint32_t result, value1, value2;
    u_char buffer[9];

    /*
        This function is intended to return true if a HTTP cookie has been set 
        indicating successful authentication previously by the current HTTP client. 
    */

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_totp_module);
    /* assert(lcf != NULL); */
    cookie = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie,
            &lcf->cookie,
            &value);
    if (cookie == NULL) {
        return 0;
    }

    /*
        It should be noted that the validation mechanism for the cookie value is 
        very primitive, merely checking to see whether the value appears to have 
        been set by this module. This is because there is no inherent value in the
        cookie beyond its' presence in the HTTP request.
    */

    if (value.len != 24) {
        return 0;
    }
    ngx_memzero(buffer, sizeof(buffer));
    ngx_memmove(buffer, &value.data[0], 8);
    value1 = strtoul((char *)buffer, (char **)NULL, 16);
    ngx_memmove(buffer, &value.data[8], 8);
    value2 = strtoul((char *)buffer, (char **)NULL, 16);
    ngx_memmove(buffer, &value.data[16], 8);
    result = strtoul((char *)buffer, (char **)NULL, 16);

    return ((value1 ^ value2) == result);
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
    ngx_err_t err;
    ngx_fd_t fd;
    ngx_file_t file;
    ngx_int_t rc;
    ngx_str_t filename, realm;
    ngx_uint_t count, index, length, level, state;
    u_char buffer[NGX_HTTP_AUTH_TOTP_BUF_SIZE];
    off_t offset;
    ssize_t rv;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_totp_module);
    /* assert(lcf != NULL); */
    if ((lcf->realm == NULL) ||
            (lcf->totp_file == NULL)) {
        return NGX_DECLINED;
    }

    if (ngx_http_complex_value(r, lcf->realm, &realm) != NGX_OK) {
        return NGX_ERROR;
    }
    if ((realm.len == 3) &&
            (ngx_strncasecmp(realm.data, (u_char *) "off", 3) == 0)) {
        return NGX_DECLINED;
    }
    if (ngx_http_auth_totp_get_cookie(r) != 0) {
        return NGX_OK;
    }

    /*
        If the client has not provided username and/or password, the WWW-Authenticate 
        header is sent to demand basic authentication.
    */
    
    rc = ngx_http_auth_basic_user(r);
    if (rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "no user/password was provided for basic authentication");
        return ngx_http_auth_totp_set_realm(r, &realm);
    }
    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /*
        The following code is intended to perform parsing of the TOTP configuration 
        file to read the parameters to be employed in association witht he TOTP 
        algorithm based on the user name included in Basic Authentication headers.
    */

    if (ngx_http_complex_value(r, lcf->totp_file, &filename) != NGX_OK) {
        return NGX_ERROR;
    }

    fd = ngx_open_file(filename.data, NGX_FILE_RDONLY, NGX_FILE_OPEN, 0);
    if (fd == NGX_INVALID_FILE) {
        err = ngx_errno;

        if (err == NGX_ENOENT) {
            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
        }
        else {
            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_log_error(level, r->connection->log, err,
                ngx_open_file_n " \"%s\" failed", filename.data);

        return rc;
    }

    ngx_memzero(&file, sizeof(ngx_file_t));
    file.fd = fd;
    file.name = filename;
    file.log = r->connection->log;

    count = 0;
    length = 0;
    offset = 0;
    state = STATE_USER;
    rc = NGX_OK;

    for (;;) {
        rv = ngx_read_file(&file, buffer + count, NGX_HTTP_AUTH_TOTP_BUF_SIZE - count, offset);
        if (rv == NGX_ERROR) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto finish;
        }
        if (rv == 0) {
            break;
        }

        /* assert(rv > 0); */
        for (index = count; index < (count + rv); index++) {
            switch (state) {
                case STATE_USER:

                    /*
                        This parsing code differs from the reference code within the 
                        src/http/modules/ngx_http_auth_basic_module.c in that matching against the 
                        user name is not performed until the entire field has been parsed from the 
                        TOTP file. 
                    */

                    if (length == 0) {
                        if ((buffer[index] == '#') ||
                                (buffer[index] == CR)) {
                            state = STATE_SKIP;
                            break;
                        }
                        if ((buffer[index] == ' ') ||
                                (buffer[index] == '\t') ||
                                (buffer[index] == LF)) {
                            break;
                        }
                    }
                    if (buffer[index] == ':') {
                        if (length == 0) {

                            /*
                                If no user name has been specified within the TOTP file, the line is treated 
                                as junk and ignored. An alternate approach may however be to use associated 
                                TOTP algorithm parameters to match any user name provided - This behaviour 
                                may be adopted in the future.
                            */

                            state = STATE_SKIP;
                            break;
                        }
                        /* assert(index >= length); */
                        if ((r->headers_in.user.len != length) ||
                                (ngx_strncasecmp(r->headers_in.user.data, 
                                        &buffer[index - length], 
                                        length) != 0)) {
                            state = STATE_SKIP;
                            break;
                        }

                        state = STATE_SECRET;
                        length = 0;
                        break;
                    }

                    ++length;
                    break;

                case STATE_SECRET:
                    if ((buffer[index] == CR) ||
                            (buffer[index] == LF)) {
                        rc = ngx_http_auth_totp_validation(r, 
                                &realm, 
                                &buffer[index - length], 
                                length, 
                                lcf->start, 
                                lcf->step, 
                                lcf->length);
                        goto finish;
                    }
                    if (buffer[index] == ':') {
                        state = STATE_START;
                        break;
                    }

                    ++length;
                    break;

                case STATE_START:
                    if ((buffer[index] == CR) ||
                            (buffer[index] == LF)) {
                    }
                    if (buffer[index] == ':') {
                        state = STATE_STEP;
                        break;
                    }
                    break;

                case STATE_STEP:
                    if ((buffer[index] == CR) ||
                            (buffer[index] == LF)) {
                    }
                    if (buffer[index] == ':') {
                        state = STATE_LENGTH;
                    }
                    break;

                case STATE_LENGTH:
                    if ((buffer[index] == CR) ||
                            (buffer[index] == LF)) {
                    }
                    break;

                case STATE_SKIP:
                default:
                    if (buffer[index] == LF) {
                        state = STATE_USER;
                        length = 0;
                    }
                    break;
            }
        }
        offset += rv;
    }

finish:
    if (ngx_close_file(file.fd) == NGX_FILE_ERROR) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, ngx_errno,
                ngx_close_file_n " \"%s\" failed", filename.data);
    }
    ngx_explicit_memzero(buffer, NGX_HTTP_AUTH_TOTP_BUF_SIZE);

    return rc;
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
    ngx_conf_merge_value(conf->length, prev->length, 6);
    ngx_conf_merge_value(conf->skew, prev->skew, 1);
    ngx_conf_merge_sec_value(conf->start, prev->start, 0);
    ngx_conf_merge_sec_value(conf->step, prev->start, 30);
    ngx_conf_merge_str_value(conf->cookie, prev->cookie, "totp");
    ngx_conf_merge_sec_value(conf->expiry, prev->expiry, 0);

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_auth_totp_set_cookie(ngx_http_request_t *r) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    ngx_table_elt_t *set_cookie;
    uint32_t result, value1, value2;
    u_char *cookie, *ptr, expiry[16];
    size_t len;

    /*
        This function is intended to set a session cookie following successful 
        authentication by a client. This is required as the password provided by the 
        client in the authentication request will rotate (by design) and cannot be 
        relied upon for continued access to protected resources. Accordingly, a 
        session cookie is set and retrieved by this module, in preference to the 
        TOTP authentication, to ensure continued resource access following 
        authentication.
    */

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_totp_module);
    /* assert(lcf != NULL); */
    len = lcf->cookie.len + sizeof("; HttpOnly") + 24 /* - 1 + 1 */;
    if (lcf->expiry) {
        /* ngx_memzero(expiry, sizeof(expiry)); */
        ngx_snprintf(expiry, sizeof(expiry), "%ui", lcf->expiry);
        len += sizeof("; Max-Age=") + ngx_strlen(expiry) - 1;
    }

    value1 = (uint32_t) ngx_random();
    value2 = (uint32_t) ngx_random();
    result = value1 ^ value2;

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }
    ptr = ngx_copy(cookie, lcf->cookie.data, lcf->cookie.len);
    *ptr++ = '=';
    ptr = ngx_sprintf(ptr, "%08xd%08xd%08xd; HttpOnly",
            value1,
            value2,
            result);
    if (lcf->expiry) {
        ptr = ngx_sprintf(ptr, "; Max-Age=%ui", lcf->expiry);
    }

    set_cookie = ngx_list_push(&r->headers_out.headers);
    if (set_cookie == NULL) {
        return NGX_ERROR;
    }
    set_cookie->hash = 1;
    ngx_str_set(&set_cookie->key, "Set-Cookie");
    set_cookie->value.len = ptr - cookie;
    set_cookie->value.data = cookie;

    return NGX_OK;
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


static ngx_int_t
ngx_http_auth_totp_validation(ngx_http_request_t *r, ngx_str_t *realm, u_char *key, size_t length, time_t start, time_t step, size_t digits) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    uint64_t count, index;
    u_char buffer[8];
    time_t now;

    /*
        This function is intended to validate the time-based one-time password (TOTP) 
        provided by the user, using the HMAC secret, UNIX start time, time step size 
        and truncation length provided. This function additionally loops through the 
        current and previous time steps when performing the TOTP calculation to 
        accommodate skew configuration.
    */

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_totp_module);
    /* assert(lcf != NULL); */
    digits = (digits < 1) ? 1 : digits;
    digits = (digits > 8) ? 8 : digits;
    if (r->headers_in.passwd.len != digits) {
        return ngx_http_auth_totp_set_realm(r, realm);
    }

    now = time(NULL);
    if (start > now) {
        return ngx_http_auth_totp_set_realm(r, realm);
    }

    count = (now - start) / ((step > 0) ? step : 1);
    for (index = 0; index <= (uint64_t)lcf->skew; index++) {
        /* assert(count >= index); */
        ngx_snprintf(buffer, sizeof(buffer), "%0*i", 
                digits, ngx_http_auth_totp_algorithm_hotp(key, length, count - index, digits));
        if (ngx_strncmp(r->headers_in.passwd.data, buffer, digits) == 0) {
            ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                    "%s: user \"%*s\", code %*s, skew %ui",
                    MODULE_NAME,
                    r->headers_in.user.len,
                    r->headers_in.user.data,
                    digits,
                    buffer,
                    index);
            return ngx_http_auth_totp_set_cookie(r);
        }
    }

    return ngx_http_auth_totp_set_realm(r, realm);
}


