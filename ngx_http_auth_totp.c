#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <stdint.h>
#include <time.h>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#include "ngx_http_auth_totp.h"

#define NGX_HTTP_AUTH_COOKIE_HMAC_LEN (2u * (size_t)EVP_MD_size(EVP_sha1())) /* 40 bytes hex */

static uint32_t ngx_http_auth_totp_algorithm_hotp(u_char *key, size_t length, uint64_t count, size_t digits);

static void * ngx_http_auth_totp_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_auth_totp_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_auth_totp_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_totp_initialise(ngx_conf_t *cf);

static char * ngx_http_auth_totp_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_auth_totp_reuse_check(ngx_http_request_t *r, uint64_t step);

static ngx_int_t ngx_http_auth_totp_reuse_cleanup(ngx_http_request_t *r, uint64_t step);

static ngx_int_t ngx_http_auth_totp_set_cookie(ngx_http_request_t *r);

static ngx_int_t ngx_http_auth_totp_set_realm(ngx_http_request_t *r, ngx_str_t *realm);

static ngx_int_t ngx_http_auth_totp_shm_initialise(ngx_shm_zone_t *shm_zone, void *data);

static ngx_int_t ngx_http_auth_totp_validation(ngx_http_request_t *r, ngx_str_t *realm, u_char *key, size_t length, time_t start, time_t step, size_t digits);

static u_char * ngx_http_auth_totp_generate_hmac_hex(u_char *buf, size_t buf_len, u_char *msg, size_t msg_len, ngx_str_t secret_key);

static ngx_int_t powi[] = { 1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000 };


static ngx_command_t ngx_http_auth_totp_directives[] = {

    { ngx_string("auth_totp_cookie"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_str_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, cookie),
            NULL },

    { ngx_string("auth_totp_secret"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_str_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, totp_secret),
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

    { ngx_string("auth_totp_reuse"),
            NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
            ngx_conf_set_flag_slot,
            NGX_HTTP_LOC_CONF_OFFSET,
            offsetof(ngx_http_auth_totp_loc_conf_t, reuse),
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
    ngx_str_t name;

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
    lcf->reuse = NGX_CONF_UNSET;

    /*
        The following creates shared memory where successful authentication for 
        current time-step windows can be recorded. This is to prevent the re-use of 
        TOTP codes (for a given user) against the validating system in line with 
        RFC 6238. The use of shared memory is so that this information may be shared 
        between nginx worker processes. 
    */

    ngx_str_set(&name, MODULE_NAME);
    lcf->shm = ngx_shared_memory_add(cf, &name, 65536, &ngx_http_auth_totp_module);
    if (lcf->shm == NULL) {
        return NULL;
    }
    lcf->shm->init = ngx_http_auth_totp_shm_initialise;

    return lcf;
}


static ngx_int_t 
ngx_http_auth_totp_get_cookie(ngx_http_request_t *r) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    ngx_table_elt_t *cookie;
    ngx_str_t value;
    ngx_str_t payload;
    ngx_str_t signature;
    ngx_str_t encoded_username;
    ngx_str_t decoded_username;
    ngx_str_t expiration;
    u_char *split_point;
    time_t expiration_time;
    u_char server_sig[NGX_HTTP_AUTH_COOKIE_HMAC_LEN];
    u_char *server_sig_end;

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

    split_point = ngx_strlchr(value.data, value.data + value.len, '|');
    if (split_point == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "%s: missing separator '|' in cookie",
                MODULE_NAME);
        return 0;
    }

    payload.data = value.data;
    payload.len = split_point - payload.data;

    signature.data = split_point + 1;
    signature.len = (value.data + value.len) - (split_point + 1);
    if (NGX_HTTP_AUTH_COOKIE_HMAC_LEN != signature.len) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "%s: incorrect cookie signature length (got %d, expected %d)",
                MODULE_NAME, signature.len, NGX_HTTP_AUTH_COOKIE_HMAC_LEN);
        return 0;
    }

    split_point = ngx_strlchr(payload.data, payload.data + payload.len, '^');
    if (split_point == NULL) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "%s: missing separator '^' in cookie", MODULE_NAME);
        return 0;
    }
    encoded_username.data = payload.data;
    encoded_username.len = split_point - encoded_username.data;
    expiration.data = split_point + 1;
    expiration.len = payload.len - (encoded_username.len + 1);

    //  Deny access if cookie format is invalid
    if (encoded_username.len == 0 || expiration.len == 0) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "%s: cookie format is invalid", MODULE_NAME);
        return 0;
    }

    //  Check if expiration date has passed
    expiration_time = ngx_atotm(expiration.data, expiration.len);
    if ((expiration_time == NGX_ERROR) ||
            ((expiration_time != 0) && (expiration_time < ngx_time()))) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "%s: cookie is expired or invalid (timestamp:%T now:%T)",
                MODULE_NAME, expiration_time, ngx_time());
        return 0;
    }

    //  Check cookie username against basic auth username
    decoded_username.len = encoded_username.len + 1; // More than long enough
    decoded_username.data = ngx_pnalloc(r->pool, decoded_username.len);
    if (decoded_username.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: failed to decode username of length %uz",
                MODULE_NAME, encoded_username.len);
        return 0;
    }
    //  Note: ngx_decode_base64() changes len property to the exact decoded length
    if (ngx_decode_base64url(&decoded_username, &encoded_username) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: base64 decoding unsuccessful", MODULE_NAME);
        return 0;
    }
    if (decoded_username.len != r->headers_in.user.len ||
            (ngx_memcmp(decoded_username.data, r->headers_in.user.data,
            decoded_username.len) != 0)) {
        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                "%s: cookie username mismatch", MODULE_NAME);
        return 0;
    }

    //  Verify cookie authenticity
    server_sig_end = ngx_http_auth_totp_generate_hmac_hex(server_sig, sizeof(server_sig),
            payload.data, payload.len, lcf->totp_secret);
    if (server_sig_end != (server_sig + sizeof(server_sig))) {
        return 0;
    }
    if (CRYPTO_memcmp(server_sig, signature.data, NGX_HTTP_AUTH_COOKIE_HMAC_LEN) != 0) {
        ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                "%s: invalid cookie signature", MODULE_NAME);
        return 0;
    }

    return 1;
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

    if (lcf->totp_secret.len == 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: auth_totp_secret not set; denying request",
                MODULE_NAME);
        return NGX_DECLINED;
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

    if (ngx_http_auth_totp_get_cookie(r) != 0) {
        return NGX_OK;
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

                    ++length;
                    break;

                case STATE_START:   //  For future use
                case STATE_STEP:    //  For future use
                case STATE_LENGTH:  //  For future use
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
    // user not found in TOTP file
    rc = ngx_http_auth_totp_set_realm(r, &realm);

    rc = ngx_http_auth_totp_set_realm(r, &realm);

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
    ngx_conf_merge_str_value(conf->totp_secret, prev->totp_secret, "");
    ngx_conf_merge_sec_value(conf->expiry, prev->expiry, 0);
    ngx_conf_merge_value(conf->reuse, prev->reuse, 0);

    if (conf->shm == NULL) {
        conf->shm = prev->shm;
    }

    return NGX_CONF_OK;
}


static ngx_int_t 
ngx_http_auth_totp_reuse_check(ngx_http_request_t *r, uint64_t step) {
    ngx_http_core_loc_conf_t *clcf;
    ngx_http_auth_totp_loc_conf_t *lcf;
    ngx_http_auth_totp_shm_t *shm; 
    ngx_str_node_t *n;
    u_char buffer[NGX_HTTP_AUTH_TOTP_BUF_SIZE], *ptr;
    ngx_str_t value;
    ngx_int_t result;
    uint32_t hash;

    /*
        This function is intended to check for previous successful authentication by 
        the current user for the given TOTP step window. If the user has already 
        successfully authenticated within the given step window for the given 
        location directive, a non-zero value will returned by this function.

        The inclusion of the URI from the associated location directive allows for 
        authentication to be independent between location directives.
    */

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
    /* assert(clcf != NULL); */
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_totp_module);
    /* assert(lcf != NULL); */
    if (lcf->reuse != 0) {
        return 0;
    }

    /*
        The step value must be at the start of the red-black tree key - This is so 
        as to facilitate comparison actions in the ngx_http_auth_totp_reuse_cleanup 
        function.
    */

    ptr = ngx_snprintf(buffer, sizeof(buffer), "%ui:%V:%V",
            step,
            &clcf->name, 
            &r->headers_in.user);
    value.data = buffer;
    value.len = ptr - buffer;
    hash = ngx_crc32_long(value.data, value.len);

    result = -1;
    shm = lcf->shm->data;
    /* assert(shm != NULL); */
    n = (ngx_str_node_t *) ngx_str_rbtree_lookup(&shm->tree, &value, hash);
    if (n != NULL) {
        result = 1;
        goto finish;
    }

    n = ngx_slab_alloc(shm->shpool, sizeof(ngx_str_node_t));
    if (n == NULL) {
        goto finish;
    }
    ptr = ngx_slab_alloc(shm->shpool, value.len);
    if (ptr == NULL) {
        goto finish;
    }
    ngx_memcpy(ptr, value.data, value.len);
    n->str.data = ptr;
    n->str.len = value.len;
    n->node.key = hash;
    ngx_shmtx_lock(&shm->shpool->mutex);
    ngx_rbtree_insert(&shm->tree, &n->node);
    ngx_shmtx_unlock(&shm->shpool->mutex);

    result = 0;

finish:
    return result;
}


static ngx_int_t 
ngx_http_auth_totp_reuse_cleanup(ngx_http_request_t *r, uint64_t step) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    ngx_http_auth_totp_shm_t *shm;
    ngx_rbtree_t *tree;
    ngx_rbtree_node_t *node;
    ngx_str_node_t *n;
    ngx_array_t entries;
    ngx_uint_t index;
    ngx_str_t *entry, *name;
    uint64_t value;
    uint32_t hash;

    /*
        The function is intended to walk through the red-black tree of successful 
        authentication requests and remove any entries whose associated validity 
        window has expired. This is primarily to maintain a "clean" memory 
        environment without any lingering entries associated with expired 
        authentication entries.

        This is performed by building an array of expired authentication requests
        and then deleting these _after_ completing the iteration of the red-black
        tree.
    */

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_totp_module);
    /* assert(lcf != NULL); */
    shm = lcf->shm->data;
    /* assert(shm != NULL); */
    tree = &shm->tree;

    if (tree->root == tree->sentinel) {
        return 0;
    }

    ngx_array_init(&entries, r->pool, 16, sizeof(ngx_str_t));
    for (node = ngx_rbtree_min(tree->root, tree->sentinel); 
            node; 
            node = ngx_rbtree_next(tree, node)) {

        n = (ngx_str_node_t *) node;
        value = strtoll((char *) n->str.data, NULL, 10);
        if (value < step) {
            name = ngx_pnalloc(r->pool, sizeof(ngx_str_t));
            /* assert(name != NULL); */
            if (name == NULL) {
                return -1;
            }
            name->data = ngx_pstrdup(r->pool, &n->str);
            /* assert(name->data != NULL); */
            if (name->data == NULL) {
                return -1;
            }
            name->len = n->str.len;

            entry = ngx_array_push(&entries);
            *entry = *name;
        }
    }

    for (index = 0, name = entries.elts; 
            index < entries.nelts; 
            ++index) {

        hash = ngx_crc32_long(name[index].data, name[index].len);
        n = (ngx_str_node_t *) ngx_str_rbtree_lookup(tree, &name[index], hash);
        if (n != NULL) {
            /* assert(n != NULL); */
            ngx_shmtx_lock(&shm->shpool->mutex);
            ngx_rbtree_delete(tree, (ngx_rbtree_node_t *) n);
            ngx_shmtx_unlock(&shm->shpool->mutex);
        }
    }

    return 0;
}


static ngx_int_t
ngx_http_auth_totp_set_cookie(ngx_http_request_t *r) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    ngx_table_elt_t *set_cookie;
    u_char *cookie, *ptr;
    ngx_str_t payload_str;
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

    if (r->headers_in.user.len == 0) {
        return NGX_ERROR;
    }

    //  Allocate buffer sufficient for "cookiename=user^expiry|hmac; HttpOnly"
    len = lcf->cookie.len
            + 1                                 // =
            + ngx_base64_encoded_length(r->headers_in.user.len)
            + 1                                 // ^
            + NGX_INT64_LEN                     // time is cast to int64_t in ngx_vslprintf()
            + 1                                 // |
            + NGX_HTTP_AUTH_COOKIE_HMAC_LEN
            + sizeof("; HttpOnly");
    if (lcf->expiry) {
        len += sizeof("; Max-Age=") + NGX_INT64_LEN;
    }

    cookie = ngx_pnalloc(r->pool, len);
    if (cookie == NULL) {
        return NGX_ERROR;
    }
    ptr = ngx_copy(cookie, lcf->cookie.data, lcf->cookie.len);
    *ptr++ = '=';

    //  Add username (base64 encoded) and time
    payload_str.data = ptr;
    payload_str.len = (cookie + len) - ptr;
    ngx_encode_base64url(&payload_str, &r->headers_in.user);
    if (payload_str.len < r->headers_in.user.len) {
        // This should not be possible, but we check anyway
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: cookie username encoding failed",
                MODULE_NAME);
        return NGX_ERROR;
    }
    ptr += payload_str.len;
    *ptr++ = '^';

    if (lcf->expiry != 0) {
        ptr = ngx_sprintf(ptr,"%T", ngx_time() + (time_t) lcf->expiry);
    }
    else {
        *ptr++ = '0';
    }
    *ptr++ = '|';

    //  Compute HMAC over the cookie payload
    ptr = ngx_http_auth_totp_generate_hmac_hex(ptr, len - (ptr - cookie),
            payload_str.data,
            (ptr - 1) - payload_str.data,
            lcf->totp_secret);
    if (ptr == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                "%s: cookie HMAC generation failed", MODULE_NAME);
        return NGX_ERROR;
    }

    //  Finish up the cookie
    ptr = ngx_cpystrn(ptr, (u_char *) "; HttpOnly", (cookie + len) - ptr);
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
ngx_http_auth_totp_shm_initialise(ngx_shm_zone_t *shm_zone, void *data) {
    ngx_slab_pool_t *shpool;
    ngx_http_auth_totp_shm_t *shm;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    shm = ngx_slab_alloc(shpool, sizeof(ngx_http_auth_totp_shm_t));
    if (shm == NULL) {
        return NGX_ERROR;
    }
    ngx_rbtree_init(&shm->tree, &shm->sentinel, ngx_str_rbtree_insert_value);
    shm->shpool = shpool;
    shm_zone->data = shm;

    return NGX_OK;
}


static u_char *
ngx_http_auth_totp_generate_hmac_hex(u_char *buf, size_t buf_len, u_char *msg, size_t msg_len, ngx_str_t secret_key) {
    u_char *ptr = buf;
    unsigned int digest_len = 0;
    unsigned int hex_len;
    unsigned char raw_buf[NGX_HTTP_AUTH_COOKIE_HMAC_LEN / 2];

    if (buf_len < (NGX_HTTP_AUTH_COOKIE_HMAC_LEN)) {
        return NULL; // Caller's buffer is too small
    }

    if (secret_key.len > INT_MAX) {
        return NULL; // Key is too long
    }

    //  Write the raw HMAC into stack-allocated raw_buf
    if (HMAC(EVP_sha1(),
            secret_key.data, (int) secret_key.len,
            msg, msg_len,
            raw_buf, &digest_len) == NULL) {
        return NULL;
    }

    if (digest_len != NGX_HTTP_AUTH_COOKIE_HMAC_LEN/2) {
        return NULL;
    }

    //  Hex-encode the raw HMAC directly into passed-in buf
    for (hex_len = 0; ptr && hex_len < digest_len; ++hex_len) {
      ptr = ngx_sprintf(ptr, "%02uxd", raw_buf[hex_len]);
    }

    if (ptr != (buf + digest_len * 2)) {
        return NULL;
    }

    //  Return pointer to end of output hex
    return ptr;
}


static ngx_int_t
ngx_http_auth_totp_validation(ngx_http_request_t *r, ngx_str_t *realm, u_char *key, size_t length, time_t start, time_t step, size_t digits) {
    ngx_http_auth_totp_loc_conf_t *lcf;
    uint64_t count, index;
    u_char buffer[8];
    char fmt[] = "%00uD"; // Don't change without adjusting manipulation below
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
    fmt[2] = '0' + digits;

    now = time(NULL);
    if (start > now) {
        return ngx_http_auth_totp_set_realm(r, realm);
    }

    count = (now - start) / ((step > 0) ? step : 30);
    ngx_http_auth_totp_reuse_cleanup(r, count - lcf->skew);

    for (index = 0; index <= (uint64_t)lcf->skew; index++) {
        /* assert(count >= index); */
        ngx_snprintf(buffer, sizeof(buffer), fmt,
                ngx_http_auth_totp_algorithm_hotp(key, length, count - index, digits));
        if (ngx_strncmp(r->headers_in.passwd.data, buffer, digits) == 0) {

            if (ngx_http_auth_totp_reuse_check(r, count - index) != 0) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                        "%s: attempted password re-use by user \"%*s\"",
                        MODULE_NAME,
                        r->headers_in.user.len,
                        r->headers_in.user.data);
                break;
            } 
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


