/*#############################################
#
# Title:        mod_but.h
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/

#ifndef MOD_BUT_H
#define MOD_BUT_H

#define PC_LOG_INFO APLOG_MARK,APLOG_INFO,0
#define PC_LOG_CRIT APLOG_MARK,APLOG_CRIT,0

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



/********************************************************************
	DEFAULT VALUES
*/
#ifndef MOD_BUT_COOKIE_NAME
#define MOD_BUT_COOKIE_NAME	"MOD_BUT"   	///< The name of the session cookie
#endif

#ifndef MOD_BUT_COOKIE_DOMAIN
#define MOD_BUT_COOKIE_DOMAIN	""   		///< Cookie Domain Specifier
#endif

#ifndef MOD_BUT_COOKIE_PATH
#define MOD_BUT_COOKIE_PATH	"/"   		///< The path of the cookie
#endif

#ifndef MOD_BUT_COOKIE_REFUSE_URL
#define MOD_BUT_COOKIE_REFUSE_URL	"/mod_but/error/refused_cookies.html"   ///< URL, if client refuses the set-cookie header and if not configured in httpd.conf
#endif

#ifndef MOD_BUT_SESSION_FREE_URL
#define MOD_BUT_SESSION_FREE_URL	"(^/robots.txt)|(^/favicon.ico)"   ///< FREE URL's (session not required for theses regexp URL's)
#endif


#ifndef MOD_BUT_COOKIE_EXPIRATION
#define MOD_BUT_COOKIE_EXPIRATION	""   	///< The expiration date of the cookie
#endif

//	On=1	Off=0
#ifndef MOD_BUT_COOKIE_SECURE
#define MOD_BUT_COOKIE_SECURE        1   	///< http or https cookie behaviour
#endif

#ifndef MOD_BUT_COOKIE_HTTPONLY
#define MOD_BUT_COOKIE_HTTPONLY      1   	///< HTTPonly flag (for IE ONLY)
#endif


#ifndef MOD_BUT_DEFAULT_SHM_SIZE
#define MOD_BUT_DEFAULT_SHM_SIZE	"32768"   ///< Default Shared Memory Segment
#endif

#ifndef MOD_BUT_SESSION_TIMEOUT
#define MOD_BUT_SESSION_TIMEOUT        3600   	/// Session timeout in seconds
#endif


#ifndef MOD_BUT_SESSION_ATTEMPT_URL
#define MOD_BUT_SESSION_ATTEMPT_URL    "/mod_but/error/session_invalid.html"	/// Session hacking attempt
#endif

#ifndef MOD_BUT_SESSION_INACTIVITY_TIMEOUT
#define MOD_BUT_SESSION_INACTIVITY_TIMEOUT        900   	/// Session inactivity timeout in seconds
#endif

#ifndef MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL
#define MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL     "/mod_but/error/session_inactivity.html"   	/// Session inactivity timeout url
#endif

#ifndef MOD_BUT_SESSION_TIMEOUT_URL
#define MOD_BUT_SESSION_TIMEOUT_URL	       "/mod_but/error/session_expired.html"   	/// Session timeout history in seconds
#endif


#ifndef MOD_BUT_SESSION_TIMEOUT_HISTORY
#define MOD_BUT_SESSION_TIMEOUT_HISTORY        28800   	/// Session timeout history in seconds
#endif

#ifndef MOD_BUT_SESSION_RENEW_URL
#define MOD_BUT_SESSION_RENEW_URL        "(^/renew/)"   	/// regexp when a session shall be renewed
#endif

#ifndef MOD_BUT_SESSION_DESTROY
#define MOD_BUT_SESSION_DESTROY        "(^/logout/)"   	/// session destroy regexp
#endif


#ifndef MOD_BUT_SESSION_DESTROY_URL
#define MOD_BUT_SESSION_DESTROY_URL        "/mod_but/error/session_destroy.html"   	/// session destroy url
#endif

#ifndef MOD_BUT_LOGON_SERVER_URL
#define MOD_BUT_LOGON_SERVER_URL        "/mod_but/login.html"   	///< URL for global logon server (default)
#endif

#ifndef MOD_BUT_LOGON_SERVER_URL_1
#define MOD_BUT_LOGON_SERVER_URL_1        "/mod_but/login.html"   	///< URL for global logon server (username & password)
#endif

#ifndef MOD_BUT_LOGON_SERVER_URL_2
#define MOD_BUT_LOGON_SERVER_URL_2        "/mod_but/login.html"   	///< URL for global logon server (strong authentication)
#endif


#ifndef MOD_BUT_LOGON_AUTH_COOKIE_NAME
#define MOD_BUT_LOGON_AUTH_COOKIE_NAME        "LOGON"   	///< Cookiename for authentication
#endif

#ifndef MOD_BUT_LOGON_AUTH_COOKIE_VALUE
#define MOD_BUT_LOGON_AUTH_COOKIE_VALUE        "ok"   	///< Cookievalue for successful authentication
#endif

#ifndef MOD_BUT_SHM_USED_URL
#define MOD_BUT_SHM_USED_URL        "/mod_but/error/session_shm_used.html"   	///< URL if a shm problem occours
#endif

#ifndef MOD_BUT_FREE_COOKIES
#define MOD_BUT_FREE_COOKIES        "(^language=.*)|(^trustme=.*)"   	///< cookies not stored in cookie store
#endif

#ifndef MOD_BUT_SERVICE_LIST_COOKIE_NAME
#define MOD_BUT_SERVICE_LIST_COOKIE_NAME	"MOD_BUT_SERVICE_LIST"   	///< The name of the  cookie
#endif

#ifndef MOD_BUT_SERVICE_LIST_COOKIE_VALUE
#define MOD_BUT_SERVICE_LIST_COOKIE_VALUE	"(^/.*$)"   	///< default service list
#endif

#ifndef MOD_BUT_SERVICE_LIST_ERROR_URL
#define MOD_BUT_SERVICE_LIST_ERROR_URL	"/mod_but/error/authorization_error.html"   	///< authorization error
#endif

#ifndef MOD_BUT_AUTHORIZED_LOGON_URL
#define MOD_BUT_AUTHORIZED_LOGON_URL	"(^/.*$)"   	///< from what r->uri LOGON=ok cookies are accepted
#endif



/***********************
	20000 sessions require about 30 seconds to start (init) and allocate 6 MB
	10000 sessions require about 10 seconds to start (init) and allocate 3 MB

*/
#ifndef MOD_BUT_SESSION_COUNT
#define MOD_BUT_SESSION_COUNT 1000   ///< Default number of mod_but sessions (SHM)
#endif

#ifndef MOD_BUT_SESSION_HISTORY_COUNT
#define MOD_BUT_SESSION_HISTORY_COUNT	1000   ///< How many history sessions? (SHM)
#endif

#ifndef MOD_BUT_COOKIESTORE_COUNT
#define MOD_BUT_COOKIESTORE_COUNT	3000  ///< Default cookiestore size (SHM)
#endif
/********************************************************************
	MODULE DECLARATION
*/
module AP_MODULE_DECLARE_DATA but_module;




/********************************************************************
	CONFIG STRUCTURE FOR APACHE STARTING PROCEDURE
*/
typedef struct {
	int enabled;					// [On, Off] switch for enable/disable mod_but
	const char *client_refuses_cookies_url;		// Error URL, if the client refuses our mod_but cookie
	const char *cookie_name;			// The cookie name value of the mod_but cookie
	const char *cookie_domain;			// The cookie domain value
	const char *cookie_path;			// The cookie path value
	const char *cookie_expiration;			// The cookie expiration flag value
	int cookie_secure;			// The cookie secure flag value
	int cookie_httponly;			// The HTTPonly flag (for MS IE only)
	const char *session_free_url;			// Regexp statement, for which mod_but is not enforced

	apr_int64_t session_timeout;				// How long a mod_but session is accepted, before a new must be given
	const char *session_expired_url;		// Error URL, once a session times out (expires)
	const char *session_renew_url;	// URL for which MOD_BUT sets new MOD_BUT session

	const char *session_hacking_attempt_url; 		// Error URL, if the client sends a guessed/invalid mod_but cookie

	apr_int64_t session_inactivity_timeout;			// How long the client can do *nothing*, before it's session expires
	const char *session_inactivity_timeout_url;	// Error URL, once the inactivity timout is reached


	const char *all_shm_space_used_url;		// Error URL, if all sessions are taken by mod_but and NO shm available

	apr_int64_t session_timeout_history;			// Timeout for SHM Session History

	const char *session_destroy;			// Session destroy URI
	const char *session_destroy_url;		// Error URL, once we have destroyed the session

	int authorization_enabled;

	const char *global_logon_server_url;			// Logon Server URI
	const char *global_logon_server_url_1;
	const char *global_logon_server_url_2;
	const char *global_logon_auth_cookie_name;	// Cookie Name, which is used as authenticator
	const char *global_logon_auth_cookie_value;	// Cookie Value, which is used as authenticator

	const char *session_store_free_cookies;		// The cookies configured here are not handled by the session store

	const char *service_list_cookie_name;		// service list cookie name
	const char *service_list_cookie_value;		// service list
	const char *service_list_error_url;		// error, if user is not authorized
	int service_list_enabled_on;
	const char *authorized_logon_url;		// Regexp from what r->uri LOGON=ok are accepted

} mod_but_server_t;


typedef struct {
	const char *logon_server_url;			// Logon Server URI
	const char *logon_required;			// On or Off
	const int  mod_but_location_id;			// to group the backend sessions
	const int  mod_but_auth_strength;		// required authentication strength per directory
} mod_but_dir_t;


/********************************************************************
	SHM STRUCTURE FOR MOD_BUT SESSION
*/
typedef struct {
        char     	session_name[100];    		///< The name of this cookie
        char     	session_value[100];  		///< The value of this cookie
        char     	session_firsturl[100];   	///< Used to save the original URL from the first request for redirection purpose
	int		session_create_time;
	int	 	session_last_access_time;
	int		link_to_cookiestore;
	int		logon_state;			/// 0 = not logged in, 1 = logged in
        char     	orig_url_before_logon[100];   	///< URL before logon is done
	char		service_list[100];
	int		logon_flag;
	int		auth_strength;
} mod_but_cookie;

/********************************************************************
	SHM STRUCTURE FOR MOD_BUT SESSION HISTORY
*/
typedef struct {
        char     	session_value[100];  		///< The value of this cookie
	apr_time_t 	session_delete_time;
} mod_but_cookie_history;


/********************************************************************
	SHM STRUCTURE FOR COOKIE_STORE
*/
typedef struct {
	char		cookie_name[100];
	char		cookie_value[100];
	int		cookie_next;
	int 		cookie_before;
	int		cookie_slot_used;
	int		location_id;
} mod_but_cookie_cookiestore;


typedef struct {
        request_rec *r;
        char *cookie;
} cookie_res;


/********************************************************************
	DECLARATION (removes warning at compile time)
*/
char *ssl_var_lookup(apr_pool_t *p, server_rec *s, conn_rec *c, request_rec *r, char *var);

/********************************************************************
	HELPER FUNCTIONS in mod_but_access.c
*/
void find_cookie_try(request_rec *r);
int analyze_request_arguments_for_cookie_test(request_rec *r);
int analyze_request_uri_for_session_destroy(request_rec *r);

/********************************************************************
	SESSION FUNCTIONS in mod_but_session.c
*/
int create_new_mod_but_session(request_rec *r);
int create_new_mod_but_session_renew(request_rec *r);
int validation_of_client_sent_session(request_rec *r);
int delete_mod_but_session(apr_int64_t shmoff, request_rec *r);
int renew_mod_but_session(apr_int64_t shmoffold, request_rec *r);


/********************************************************************
        SHM FUNCTIONS in mod_but_shm.c
*/
apr_status_t mod_but_shm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
apr_status_t shm_cleanup(void *not_used);
apr_rmm_t *find_cs_rmm();
apr_rmm_off_t *find_cs_rmm_off();

apr_status_t mod_but_shm_initialize_history(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
apr_status_t shm_cleanup_history(void *not_used);
apr_rmm_t *find_cs_rmm_history();
apr_rmm_off_t *find_cs_rmm_off_history();

apr_status_t mod_but_shm_initialize_cookiestore(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s);
apr_status_t shm_cleanup_cookiestore(void *not_used);


int create_new_shm_session(request_rec *r, unsigned char *sid);
void cleaning_shm_from_expired_session(request_rec *r);
void cleaning_shm_history_from_expired_session(request_rec *r);
apr_rmm_t *find_cs_rmm_cookiestore();
apr_rmm_off_t *find_cs_rmm_off_cookiestore();

/********************************************************************
        COOKIE STORE FKT in mod_but_cookiestore.c
*/
int find_empty_cookiestore_slot(request_rec *r);


/********************************************************************
        AUTHORIZATION FKT in mod_but_authorization.c
*/
int do_authorization(int shm_offset_number, request_rec *r);


/********************************************************************
        CONFIGURATION FUNCTIONS in mod_but_output_filter.c

BOOL mod_but_find_set_cookie_attempt( const char* key, const char* value );
void mod_but_store_cookies_in_cookiestore( apr_table_t* header );
*/
int mod_but_analyze_response_headers(void *result, const char *key, const char *value);
//void fixup_cookiestore_chain(request_rec *r, int link_to_cookiestore, const char *value);
int store_cookie_in_cookiestore(request_rec *r, int anchor, mod_but_cookie_cookiestore *cs);
void delete_cookiestore_entries_belonging_to_a_deleting_session(request_rec *r, int anchor);
void add_headers_into_request_from_cookiestore(request_rec *r, int anchor);

/********************************************************************
        Function in mod_but_input_filter.c
*/
int mod_but_analyze_request_headers(void *result, const char *key, const char *value);

/********************************************************************
        CONFIGURATION FUNCTIONS in mod_but_config.c
*/
const char *mod_but_enabled_on(cmd_parms *cmd, void *dummy, int arg);
const char *mod_but_client_refuses_cookies(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_cookie_name(cmd_parms *cmd, void *dummy, const char *args);
const char *mod_but_set_cookie_domain(cmd_parms *cmd, void *dummy, const char *args);
const char *mod_but_set_cookie_path(cmd_parms *cmd, void *dummy, const char *args);
const char *mod_but_set_cookie_expiration(cmd_parms *cmd, void *dummy, const char *args);
const char *mod_but_set_cookie_secure(cmd_parms *cmd, void *dummy, int arg);
const char *mod_but_set_cookie_httponly(cmd_parms *cmd, void *dummy, int arg);
const char *mod_but_set_session_free_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_timeout(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_hacking_attempt_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_inactivity_timeout(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_inactivity_timeout_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_expired_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_renew_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_all_shm_used_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_timeout_history(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_destroy(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_destroy_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_authorization_enabled_on(cmd_parms *cmd, void *dummy, int arg);
const char *mod_but_global_logon_server_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_global_logon_server_url_1(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_global_logon_server_url_2(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_global_logon_auth_cookie_name(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_global_logon_auth_cookie_value(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_session_store_free_cookies(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_service_list_cookie_name(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_service_list_cookie_value(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_set_service_list_error_url(cmd_parms *cmd, void *dummy, const char *arg);
const char *mod_but_service_list_enabled_on(cmd_parms *cmd, void *dummy, int arg);
const char *mod_but_set_authorized_logon_url(cmd_parms *cmd, void *dummy, const char *arg);

#endif /*MOD_BUT_H*/
