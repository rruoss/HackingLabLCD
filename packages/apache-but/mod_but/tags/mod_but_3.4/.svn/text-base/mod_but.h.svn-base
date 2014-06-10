/* $Id: mod_but.h 147 2010-05-30 20:28:01Z ibuetler $ */

#ifndef MOD_BUT_H
#define MOD_BUT_H

#include "apr.h"
#include "apr_lib.h"
#include "apr_strings.h"
#include "apr_buckets.h"
#include "apr_hash.h"
#include "apr_want.h"
#include "apr_shm.h"
#include "apr_rmm.h"
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_log.h"
#include "util_filter.h"
#include "util_script.h"
#include "http_protocol.h"
#include "http_main.h"
#include "http_core.h"
#include "util_md5.h"
#include "pcre.h"
#include "apr_errno.h"
#include "apr_general.h"
#include "apr_time.h"
#include "ap_config.h"
#include "apr_optional.h"
#include "apr_base64.h"

#include "mod_but_debug.h"
#include "mod_but_errno.h"
#include "mod_but_compat.h"


/********************************************************************
 * configuration default values
 */
#define MOD_BUT_COOKIE_NAME			"MOD_BUT"					/* The name of the session cookie */
#define MOD_BUT_COOKIE_DOMAIN			""						/* Cookie Domain Specifier */
#define MOD_BUT_COOKIE_PATH			"/"						/* The path of the cookie */
#define MOD_BUT_COOKIE_REFUSE_URL		"/mod_but/error/refused_cookies.html"		/* URL, if client refuses the set-cookie header and if not configured in httpd.conf */
#define MOD_BUT_SESSION_FREE_URL		"^/robots\\.txt$|^/favicon\\.ico$"		/* FREE URL's (session not required for theses regexp URL's) */
#define MOD_BUT_COOKIE_EXPIRATION		""						/* The expiration date of the cookie */
#define MOD_BUT_COOKIE_SECURE			1						/* Cookie secure flag (0, 1) */
#define MOD_BUT_COOKIE_HTTPONLY			1						/* Cookie HTTPonly flag (0, 1) */
#define MOD_BUT_DEFAULT_SHM_SIZE		"32768"						/* Default Shared Memory Segment */
#define MOD_BUT_SESSION_HARD_TIMEOUT		3600						/* Session hard timeout in seconds */
#define MOD_BUT_SESSION_INACTIVITY_TIMEOUT	900						/* Session inactivity timeout in seconds */
#define MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL	"/mod_but/error/session_inactivity.html"	/* Session inactivity timeout URL */
#define MOD_BUT_SESSION_TIMEOUT_URL		"/mod_but/error/session_expired.html"		/* Session timeout URL */
#define MOD_BUT_SESSION_RENEW_URL		"^/renew/"					/* regexp when a session shall be renewed */
#define MOD_BUT_SESSION_DESTROY			"^/logout/"					/* session destroy regexp */
#define MOD_BUT_SESSION_DESTROY_URL		"/mod_but/error/session_destroy.html"		/* session destroy url */
#define MOD_BUT_LOGON_SERVER_URL		"/mod_but/login.html"				/* URL for global logon server (default) */
#define MOD_BUT_LOGON_SERVER_URL_1		"/mod_but/login.html"				/* URL for global logon server (username & password) */
#define MOD_BUT_LOGON_SERVER_URL_2		"/mod_but/login.html"				/* URL for global logon server (strong authentication) */
#define MOD_BUT_LOGON_AUTH_COOKIE_NAME		"LOGON"						/* Cookiename for authentication */
#define MOD_BUT_LOGON_AUTH_COOKIE_VALUE		"ok"						/* Cookievalue for successful authentication */
#define MOD_BUT_SHM_USED_URL			"/mod_but/error/session_shm_used.html"		/* URL if a shm problem occours */
#define MOD_BUT_FREE_COOKIES			"^language=|^trustme="				/* cookies not stored in cookie store */
#define MOD_BUT_SERVICE_LIST_COOKIE_NAME	"MOD_BUT_SERVICE_LIST"				/* The name of the  cookie */
#define MOD_BUT_SERVICE_LIST_COOKIE_VALUE	"^/.*$"						/* default service list */
#define MOD_BUT_SERVICE_LIST_ERROR_URL		"/mod_but/error/authorization_error.html"	/* authorization error */
#define MOD_BUT_AUTHORIZED_LOGON_URL		"^/.*$"						/* from what r->uri LOGON=ok cookies are accepted */
#define MOD_BUT_URL_AFTER_RENEW			"/url_after_renew/"				/* set url after renew here */
#define MOD_BUT_ENABLED_RETURN_TO_ORIG_URL	"^/.*$"						/* from what r->uri LOGON=ok cookies are accepted */


/********************************************************************
 * Compile time configuration
 */

/*
 * Session ID bytes: 192 bits of entropy is 2^64 times better security than "standard" 128 bits
 * Note that under Linux, starving entropy from /dev/random can lead to Apache blocking until
 * sufficient amounts of entropy is available.  This is an APR issue, not a mod_but issue.
 */
#define MOD_BUT_SIDBYTES		24

/*
 * Cookie test suffix; appended to URLs like host/foo/bar?__cookie_try=1
 */
#define MOD_BUT_COOKIE_TRY		"__cookie_try"

/*
 * 20000 sessions require about 30 seconds to start (init) and allocate 6 MB
 * 10000 sessions require about 10 seconds to start (init) and allocate 3 MB
 * (on a Sun E4500 Solaris 10 system with 8 400 MHz Sparc CPUs)
 *
 * These are meant to be overridden using the -D compiler/preprocessor option.
 */
#ifndef MOD_BUT_SESSION_COUNT
#define MOD_BUT_SESSION_COUNT		5000	/* Default number of mod_but sessions (SHM) */
#endif
#ifndef MOD_BUT_COOKIESTORE_COUNT
#define MOD_BUT_COOKIESTORE_COUNT	10000	/* Default cookiestore size (SHM) */
#endif


/********************************************************************
 * module declaration
 */
module AP_MODULE_DECLARE_DATA but_module;


/********************************************************************
 * configuration structures
 */
typedef struct {
	int enabled;					/* [On, Off] switch for enable/disable mod_but */
	const char *client_refuses_cookies_url;		/* Error URL, if the client refuses our mod_but cookie */
	const char *cookie_name;			/* The cookie name value of the mod_but cookie */
	const char *cookie_domain;			/* The cookie domain value */
	const char *cookie_path;			/* The cookie path value */
	const char *cookie_expiration;			/* The cookie expiration flag value */
	int cookie_secure;				/* The cookie secure flag value */
	int cookie_httponly;				/* The HTTPonly flag (for MS IE only) */
	const char *session_free_url;			/* Regexp statement, for which mod_but is not enforced */

	apr_int64_t session_hard_timeout;		/* How long a mod_but session is accepted, before a new must be given */
	apr_int64_t session_inactivity_timeout;		/* How long the client can do *nothing*, before it's session expires */
	const char *session_expired_url;		/* Error URL, once a session times out (expires); defaults to renew URL XXX */
	const char *session_renew_url;			/* URL for which MOD_BUT sets new MOD_BUT session */

	const char *all_shm_space_used_url;		/* Error URL, if all sessions are taken by mod_but and NO shm available */

	const char *session_destroy;			/* Session destroy URI */
	const char *session_destroy_url;		/* Error URL, once we have destroyed the session */

	int authorization_enabled;

	const char *global_logon_server_url;		/* Logon Server URI */
	const char *global_logon_server_url_1;
	const char *global_logon_server_url_2;
	const char *global_logon_auth_cookie_name;	/* Cookie Name, which is used as authenticator */
	const char *global_logon_auth_cookie_value;	/* Cookie Value, which is used as authenticator */

	const char *session_store_free_cookies;		/* The cookies configured here are not handled by the session store */

	const char *service_list_cookie_name;		/* service list cookie name */
	const char *service_list_cookie_value;		/* service list */
	const char *service_list_error_url;		/* error, if user is not authorized */
	int service_list_enabled_on;
	const char *authorized_logon_url;		/* Regexp from what r->uri LOGON=ok are accepted */
	const char *url_after_renew;			/* Redirect URL after renew session */

	int but_config_enabled_return_to_orig_url;	/* IF RETURN TO ORIG URL SHALL BE ENABLED/DISABLED */

} mod_but_server_t;

typedef struct {
	const char *logon_server_url;			/* Logon Server URI */
	const int logon_required;			/* is logon required? */
	const int mod_but_location_id;			/* to group the backend sessions */
	const int mod_but_auth_strength;		/* required authentication strength per directory */
} mod_but_dir_t;


/********************************************************************
 * SHM structures
 */
/* session data */
typedef struct {
	int		slot_used;
	char		session_name[32];		/* Name of session cookie */
	char		session_id[MOD_BUT_SIDBYTES/3*4+1]; /* Value of session cookie, MOD_BUT_SIDBYTES random bytes, Base64 */
	char		url[100];			/* Used to store URLs for client redirection */
	int		ctime;
	int		atime;
	int		cookiestore_index;		/* index of first cookie in cookie store; -1 if none */
	int		logon_state;			/* 0 = not logged in, 1 = logged in */
	int		redirect_on_auth_flag;		/* Redirect client to orig_url on first authenticated request to protected URL */
	char		service_list[100];
	int		auth_strength;
	char		redirect_url_after_login[100];
} session_data_t;
/* cookie data */
typedef struct {
	int		slot_used;
	char		name[100];
	char		value[100];
	int		next;
	int		prev;
	int		location_id;
} cookie_t;

/********************************************************************
 * Session handling API structures
 */
/* Opaque session handle type, portable across processes. */
typedef int session_handle_t;
#define INVALID_SESSION_HANDLE (-1)
/* Session type for use by callers, only valid within a single process. */
typedef struct {
	session_handle_t	handle;
	session_data_t		*data;
	request_rec		*request;
	mod_but_server_t	*config;
} session_t;

/********************************************************************
 * Iterator data structure (parameters and result)
 */
typedef struct {
	/* IN */
	request_rec	*r;		/* request record */
	/* only response cookie filter */
	session_t	*session;	/* session context */

	/* OUT */
	apr_status_t	status;		/* error status from callbacks */
	apr_table_t	*headers;	/* headers to add back into headers(_out|_in) */
	/* only response cookie filter */
	int		must_renew;	/* must renew session ID */
	/* only request cookie filter */
	const char	*sessionid;	/* session ID read from cookie */
} cookie_res;

/********************************************************************
 * mod_but_redirect.c
 */
int mod_but_redirect_to_relurl(request_rec *r, const char *relurl);
int mod_but_redirect_to_cookie_try(request_rec *r, mod_but_server_t *config);
int mod_but_redirect_to_shm_error(request_rec *r, mod_but_server_t *config);
int mod_but_find_cookie_try(request_rec *r);
char *mod_but_strip_cookie_try(char *relurl);

/********************************************************************
 * mod_but_regexp.c
 */
apr_status_t mod_but_regexp_match(request_rec *r, const char *pattern, const char *subject);
apr_status_t mod_but_regexp_imatch(request_rec *r, const char *pattern, const char *subject);
apr_status_t mod_but_regexp_match_ex(request_rec *r, const char *pattern, int opts, const char *subject);

/********************************************************************
 * mod_but_cookie.c
 */
apr_status_t but_add_session_cookie_to_headers(request_rec *r, mod_but_server_t *config, apr_table_t *headers, session_t *session);
int but_add_to_headers_out_cb(void *data, const char *key, const char *value);
int but_add_to_headers_in_cb(void *data, const char *key, const char *value);

/********************************************************************
 * mod_but_access_control.c
 */
apr_status_t but_access_control(request_rec *r, session_t *session, mod_but_server_t *config, mod_but_dir_t *dconfig);

/********************************************************************
 * mod_but_response_filter.c
 */
int mod_but_filter_response_cookies_cb(void *result, const char *key, const char *value);

/********************************************************************
 * mod_but_request_filter.c
 */
int mod_but_filter_request_cookies_cb(void *result, const char *key, const char *value);

/********************************************************************
 * mod_but_session.c
 */
void but_session_init(session_t *session, request_rec *r, mod_but_server_t *config);
int but_session_isnull(session_t *session);
apr_status_t but_session_find(session_t *session, const char *session_name, const char *session_id);
apr_status_t but_session_open(session_t *session, session_handle_t handle);
apr_status_t but_session_create(session_t *session);
void but_session_unlink(session_t *session);
apr_status_t but_session_validate(session_t *session, int hard_timeout, int inactivity_timeout);
apr_status_t but_session_renew(session_t *session);
const char * but_session_get_cookies(session_t *session);
apr_status_t but_session_set_cookie(session_t *session, const char *key, const char *value, int locid);

/********************************************************************
 * mod_but_shm.c
 */
apr_status_t but_shm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
apr_status_t shm_cleanup(void *not_used);
apr_status_t but_shm_initialize_cookiestore(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
apr_status_t shm_cleanup_cookiestore(void *not_used);
/* the following SHM functions are for session internal use only */
session_data_t * get_session_by_index(int index);
void but_shm_free(session_data_t *session_data);
int but_shm_timeout(session_data_t *session_data, int hard_timeout, int inactivity_timeout);
apr_status_t create_new_shm_session(request_rec *r, const char *sid, int *session_index);
const char * collect_cookies_from_cookiestore(request_rec *r, int anchor);
void but_cookiestore_free(int anchor);
apr_status_t store_cookie_into_session(request_rec *r, session_data_t *session_data, const char *key, const char *value, int locid);

/********************************************************************
 * mod_but_config.c
 */
extern const command_rec but_cmds[];

#endif /* MOD_BUT_H */
