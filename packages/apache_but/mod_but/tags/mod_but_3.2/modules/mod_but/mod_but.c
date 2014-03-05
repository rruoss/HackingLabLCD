/*#############################################
#
# Title:        mod_but.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
/* $Id: mod_but.c 65 2008-05-30 17:05:05Z droethli $ */

#include "mod_but.h"

/*
 * This is the main file for mod_but.  Code directly called from
 * Apache should be here.  All the Apache module API glue is here.
 * We have to ensure that we are compliant with the Apache API
 * specifications.  Helper functions called from here should in
 * general use apr_status_t error handling; those errors are
 * translated to specific HTTP error codes or redirections here.
 */


/*
 * Apache output filter.  Return values:
 *	HTTP_*			HTTP status code for errors
 *	ap_pass_brigade()	to pass request down the filter chain
 *
 * This function parses the http-response headers from a backend system.
 * We want to find out if the response-header has a
 * a) Set-Cookie header which should be stored to the session store
 * b) Set-Cookie header which is configured as "free" cookie
 * c) Set-Cookie header which has a special meaning to us (Auth=ok)
 */
static apr_status_t
mod_but_output_filter(ap_filter_t *f, apr_bucket_brigade *bb_in)
{
	apr_status_t rc;
	int i, num_set_cookie, shmoffsetnew;
	char *pshm_offset_number;

	request_rec *r = f->r;

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
	if (config == NULL) {
		ERRLOG_CRIT("Could not get configuration from apache");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (!config->enabled) {
		ERRLOG_INFO("mod_but is not enabled, pass request on to next output filter");
		return ap_pass_brigade(f->next, bb_in);
	}

	cookie_res *cr = apr_palloc(r->pool, sizeof(cookie_res));
	cr->r = r;
	cr->cookie = NULL;

	/*
	 * This checks if the response has a Set-Cookie set. There could be
	 * 	a) NO Set-Cookie in response-header
	 * 	b) LOGON Set-Cookie in response-header
	 * 	c) FREE COOKIE in response-header
	 * 	d) Other's Cookies in response-header (belonging into session store)
	 */

	/*
	 * Do Header Parsing for all Response Headers. We are looking for
	 * 	a) MOD_BUT SESSION
	 * 	b) FREE COOKIES
	 * 	c) SERVICE_LIST COOKIES
	 * 	d) OTHER COOKIES
	 */
	ERRLOG_INFO("Calling apr_table_do(mod_but_analyze_response_headers)");
	apr_table_set(r->notes, "NUM_SET_COOKIE", "0");
	apr_table_do(mod_but_analyze_response_headers, cr, r->headers_out, NULL);
	ERRLOG_INFO("Finished mod_but_analyze_response_headers iteration");

	/*
	 * Unsetting all Set-Cookie Headers from Response (All but MOD_BUT_SESSION)
	 */
	apr_table_unset(r->headers_out, "Set-Cookie");
	apr_table_unset(r->err_headers_out, "Set-Cookie");
	ERRLOG_INFO("P1: Unsetting all response Set-Cookie headers");

	/*
	 * Setting FREE Cookies into the Response Header manually
	 */
	num_set_cookie = atoi(apr_table_get(r->notes, "NUM_SET_COOKIE"));
	ERRLOG_INFO("P2: Looping over %d Set-Cookies in r->notes", num_set_cookie);
	for (i = 1; i <= num_set_cookie; i++) {
		const char *v = apr_table_get(r->notes, apr_itoa(r->pool, i));
		apr_table_set(r->headers_out, "Set-Cookie", v);
		ERRLOG_INFO("Adding Set-Cookie [%s] to response header", v);
	}

	/*
	 * If apr_table_do detected a LOGON=ok Set-Cookie header, there will be a r->notes about it.
	 * Otherwise r->notes is empty.
	 */
	if (apr_table_get(r->notes, "LOGON_STATUS") != NULL) {
		ERRLOG_INFO("Logon status = [%s]", apr_table_get(r->notes, "LOGON_STATUS"));
		i = atoi(apr_table_get(r->notes, "SHMOFFSET"));
		rc = renew_mod_but_session(r, i, &shmoffsetnew);
		if (rc != STATUS_OK) {
			if (rc == STATUS_ESHM) {
				return mod_but_redirect_to_shm_error(r, config);
			}
			ERRLOG_INFO("Error renewing session");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		ERRLOG_INFO("Changing SHM offset from [%d] to [%d]", i, shmoffsetnew);

		/*
		 * This is the runtime fix, so that the other stuff will have the correct SHMOFFSET.
		 * renew_mod_but_session returned the new SHMOFFST we have to put into r->notes
		 */
		pshm_offset_number = apr_itoa(r->pool, shmoffsetnew);
		if (!pshm_offset_number) {
			ERRLOG_CRIT("Out of memory");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		apr_table_set(r->notes, "SHMOFFSET", pshm_offset_number);
		ERRLOG_INFO("End of output filter");
	}

	if (apr_table_get(r->notes, "CS_SHM") != NULL) { /* XXX rewrite this to use TRUE/FALSE error status from iterator */
		ERRLOG_CRIT("Problems with SHM Cookie Store - ALERT - No space left in SHM Cookiestore to include a processing header");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	ERRLOG_INFO("P3: Before remove output filter");
	ap_remove_output_filter(f);
	ERRLOG_INFO("P4: After remove output filter and before passing response to next filter");
	return ap_pass_brigade(f->next, bb_in);
}

/*
 * Apache access hook.  Return values:
 *	OK		we have handled the request, do not pass it on
 *	DECLINED	we have not handled the request, pass it on to next module
 *	HTTP_*		HTTP status codes for redirection or errors
 *
 * This is the most important function in mod_but. It is the core for handling
 * requests from the Internet client. It implements:
 *
 * a) MOD_BUT session is required for the requesting  URL
 * if a) is true
 *	a1) Check if the user is sending a MOD_BUT session
 *	a2) If an invalid session is sent -> redirect client to error page
 *	a3) If no session is sent -> create new session and go ahead
 *	a4) If an old session is sent -> redirect client ot error page
 *
 *	a5) If the client is sending some "free" cookies
 *
 * if a) is false
 *	b1) Check 
 */
static int
but_access(request_rec *r)
{
	int shmoffset = 0;
	apr_rmm_t *cs_rmm;
	apr_rmm_off_t *off;
	cookie_res *cr;

	char *pshm_offset_number;
	mod_but_cookie *c;
	mod_but_dir_t *dconfig;

	ERRLOG_INFO("====== START ======");

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
	if (!config) {
		ERRLOG_CRIT("Could not get configuration from apache");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (!config->enabled) {
		ERRLOG_INFO("mod_but is not enabled, skip request (DECLINED)");
		return DECLINED;
	}

	// get per-directory configuration
	dconfig = ap_get_module_config(r->per_dir_config, &but_module);
	if (!dconfig) {
		ERRLOG_INFO("Illegal Directory Config");
	}

	ERRLOG_INFO("Request %s", r->uri);


	/****************************** PART 1 *******************************************************
	 * Handle special URLs which do not require a session.
	 */

	/*
	 * Session renewal?
	 */
	switch (mod_but_regexp_match(r, config->session_renew_url, r->uri)) {
	case STATUS_MATCH:
		ERRLOG_INFO("Renew URL found [%s]", r->uri);
		switch (create_new_mod_but_session(r, r->err_headers_out, &shmoffset)) {
		case STATUS_OK:
			/* session renewed, redirecting to / */
			return mod_but_redirect_to_relurl(r, "/");
		case STATUS_ESHM:
			return mod_but_redirect_to_shm_error(r, config);
		case STATUS_ERROR:
		default:
			ERRLOG_CRIT("Error creating new session");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		break; /* not reached */

	case STATUS_NOMATCH:
		/* do nothing */
		break;

	case STATUS_ERROR:
	default:
		ERRLOG_CRIT("Error while matching MOD_BUT_SESSION_RENEW_URL");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * Session free URL?
	 */
	switch (mod_but_regexp_match(r, config->session_free_url, r->uri)) {
	case STATUS_MATCH:
		ERRLOG_INFO("Session free URL [%s]", r->uri);
		return DECLINED;

	case STATUS_NOMATCH:
		/* do nothing */
		break;

	case STATUS_ERROR:
	default:
		ERRLOG_CRIT("Error while matching MOD_BUT_SESSION_FREE_URL");
		return HTTP_INTERNAL_SERVER_ERROR;
	}


	/****************************** PART 2 *******************************************************
	 * Check of the mod_but session
	 *	a) mod_but session is not sent by client
	 *	b) mod_but session sent is invalid
	 *	c) mod_but session sent is ok
	 * The code below will only be executed if the requesting URI
	 * requires a mod_but session
	 */

	/*
	 * BUT-1 (coming from BUT-0) -> session is required
	 * Here we will first parse the request headers for
	 *
	 *	a) MOD_BUT_SESSION (will be unset, because we don't want to have it in the backend)
	 *	b) FREE COOKIES (will be accepted, if configured in httpd.conf)
	 *	c) OTHER COOKIES (will be unset)
	 */

	if (apr_table_get(r->notes, config->cookie_name)) {
		/* XXX - when does this happen? */
		ERRLOG_INFO("Session already in r->notes [%s]", apr_table_get(r->notes, config->cookie_name));
	} else {
		ERRLOG_INFO(" r->notes [%s]", apr_table_get(r->notes, config->cookie_name));
		/*
		 * iterate over all Cookie headers and unset them;
		 * cookies for backend are now in r->notes
		 */
		cr = apr_palloc(r->pool, sizeof(cookie_res));
		if (!cr) {
			ERRLOG_CRIT("Out of memory.");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		cr->r = r;
		cr->cookie = NULL;
		if (!apr_table_do(mod_but_filter_request_cookies, cr, r->headers_in, "Cookie", NULL)) {
			ERRLOG_CRIT("Error while iterating Cookie headers.");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		apr_table_unset(r->headers_in, "Cookie");
	}

	ERRLOG_INFO("Session ID [%s]", apr_table_get(r->notes, config->cookie_name));

	if (!apr_table_get(r->notes, config->cookie_name)) {
		/*
		 * 2 a) mod_but session is not sent by client
		 */
		ERRLOG_INFO("Client did not send mod_but session");
		switch (create_new_mod_but_session(r, r->err_headers_out, &shmoffset)) {
		case STATUS_OK:
			break;
		case STATUS_ESHM:
			return mod_but_redirect_to_shm_error(r, config);
		case STATUS_ERROR:
		default:
			ERRLOG_CRIT("Error creating new session");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		return mod_but_redirect_to_cookie_test(r, config);
	} else {
		/*
		 * The client has sent a session (valid or invalid)
		 */

		/* Check if session from client is valid and in SHM */
		switch (mod_but_validate_session(r, &shmoffset)) {
		case STATUS_OK:
			break;

		case STATUS_ETIMEOUT:
			/* the sent session has reached its time out */
			ERRLOG_INFO("Session timeout reached or old session from history cache");
			if (!config->session_expired_url) {
				ERRLOG_INFO("MOD_BUT_SESSION_TIMEOUT_URL not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			return mod_but_redirect_to_relurl(r, config->session_expired_url);

		case STATUS_EINACTIVE:
			/* the sent session has reached its inactivity timeout */
			ERRLOG_INFO("Session inactivity timeout reached");
			if (!config->session_inactivity_timeout_url) {
				ERRLOG_INFO("MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			return mod_but_redirect_to_relurl(r, config->session_inactivity_timeout_url);

		case STATUS_EHACKING:
			/* the sent session is invalid, guessed or hacked */
			ERRLOG_CRIT("Attack: invalid session sent by client");
			if (!config->session_hacking_attempt_url) {
				ERRLOG_INFO("MOD_BUT_SESSION_HACKING_ATTEMPT_URL not configured");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			return mod_but_redirect_to_relurl(r, config->session_hacking_attempt_url);

		case STATUS_ERROR:
		default:
			ERRLOG_CRIT("Error validating session");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/*
		 * If we are here, the client has sent a valid mod_but session
		 */
		ERRLOG_INFO("Client has sent a valid mod_but session");

		/*
		 * We will first check, if the requesting URI asks for the session destroy function
		 * This implements the "logout" functionality.
		 */
		switch (mod_but_regexp_match(r, config->session_destroy, r->uri)) {
		case STATUS_MATCH:
			ERRLOG_CRIT("Session destroy URL matched, destroying session");
			mod_but_delete_session(shmoffset, r);
			return mod_but_redirect_to_relurl(r, config->session_destroy_url);

		case STATUS_NOMATCH:
			ERRLOG_INFO("r->uri does not match session destroy URL [%s]", r->uri);
			break;

		case STATUS_ERROR:
		default:
			ERRLOG_CRIT("Error matching session destroy URL");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/*
		 * If we are here, the requesting URI does not want to be destroyed and we analyze
		 * the request for the cookie_tests.  If we are still in the cookie test phase, we
		 * have to give the client the Original URI (from the first request) as redirect
		 */
		pshm_offset_number = apr_itoa(r->pool, shmoffset);
		if (pshm_offset_number == NULL) {
			ERRLOG_INFO("Out of memory");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		ERRLOG_INFO("Setting r->notes[SHMOFFSET] to [%s]", pshm_offset_number);
		apr_table_set(r->notes, "SHMOFFSET", pshm_offset_number);

		cs_rmm = find_cs_rmm();
		off = find_cs_rmm_off();
		c = apr_rmm_addr_get(cs_rmm, off[shmoffset]);

		/*
		 * cookie is sent by the client, it is a valid session and the
		 * requesting URL contains the cookie_try parameter
		 */
		if (mod_but_find_cookie_try(r) > 0) {
			if (!c->session_firsturl) {
				ERRLOG_CRIT("Session firsturl is unset");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			ERRLOG_INFO("Client session is valid and cookie test succeeded");
			return mod_but_redirect_to_relurl(r, c->session_firsturl);
		}
		ERRLOG_INFO("Client session is valid and no cookie try in URL");

		/*
		 * If we are here, the request will be authorized.
		 */

		/*
		 * Now let's do the authorization stuff, if enabled by config.
		 */
		if (config->authorization_enabled) {
			ERRLOG_INFO("Authorization checks are enabled");
			switch (mod_but_do_authorization(r, shmoffset)) {
			case STATUS_ELOGIN:
				ERRLOG_INFO("URI requres auth, but user not logged in yet");
				/* use r->unparsed_uri instead of r->uri to safeguard against HTTP Response Splitting */
				apr_cpystrn(c->orig_url_before_logon, r->unparsed_uri, sizeof(c->orig_url_before_logon));
				ERRLOG_INFO("Storing original URL before logon [%s]", c->orig_url_before_logon);
				c->logon_flag = 1;
				ERRLOG_INFO("Setting logon_flag to [%d]", c->logon_flag);

				if (dconfig->logon_server_url) {
					/* login server is configured for this Location */
					ERRLOG_INFO("Redirecting to logon server URL [%s]", dconfig->logon_server_url);
					return mod_but_redirect_to_relurl(r, dconfig->logon_server_url);
				} else {
					/* No login server is configured for this Location */
					ERRLOG_INFO("Local logon server URL is not set [%s]", dconfig->logon_server_url);
					if (config->global_logon_server_url == NULL) {
						ERRLOG_CRIT("Global logon server URL is not set [%s]", config->global_logon_server_url);
						return HTTP_INTERNAL_SERVER_ERROR;
					}
					ERRLOG_INFO("Redirecting to global logon server URL [%s]", config->global_logon_server_url);
					return mod_but_redirect_to_relurl(r, config->global_logon_server_url);
				}
				break; /* not reached */

			case STATUS_OK:
				ERRLOG_INFO("client is sufficiently authorized or no auth required");
				break;

			case STATUS_EDENIED:
				ERRLOG_CRIT("Client authenticated but not authorized for this URL");
				if (!config->service_list_error_url) {
					ERRLOG_CRIT("Service list error URL not set");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				return mod_but_redirect_to_relurl(r, config->service_list_error_url);

			case STATUS_ESTEPUP1:
				ERRLOG_INFO("Client authenticated but auth_strength too low for this URL");
				if (!config->global_logon_server_url_1) {
					ERRLOG_CRIT("Gobal logon server URL 1 not set");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				return mod_but_redirect_to_relurl(r, config->global_logon_server_url_1);

			case STATUS_ESTEPUP2:
				ERRLOG_INFO("Client authenticated but auth_strength too low for this URL");
				if (!config->global_logon_server_url_2) {
					ERRLOG_CRIT("Global logon server URL 2 not set");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				return mod_but_redirect_to_relurl(r, config->global_logon_server_url_2);

			case STATUS_ERROR:
			default:
				ERRLOG_CRIT("Error while checking authorization");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
		} else {
			ERRLOG_INFO("Authorization checks are disabled");
		}

		/*
		 * If we are here, the client is properly authenticated and we start proceeding
		 * the request.
		 */

		/*
		 * This is the callback function, if the user was previously successfully
		 * authenticated and the c->logon_flag = 1.  The flag was set to 1 couple of
		 * lines above, if uri requires authentication but is not authenticated yet.
		 * we need to redirect the client to the OrigURL (initial uri, before authentication)
		 */
		ERRLOG_INFO("Logon flag [%d] state [%d]", c->logon_flag, c->logon_state);
		if (c->logon_flag == 1 && c->logon_state == 1) {
			if (c->orig_url_before_logon) {
				ERRLOG_INFO("Redirect to original URL before logon: [%s]", c->orig_url_before_logon);
				c->logon_flag = 0;
				return mod_but_redirect_to_relurl(r, c->orig_url_before_logon);
			} else {
				ERRLOG_CRIT("No original URL was stored! Redirecting to /.");
				return mod_but_redirect_to_relurl(r, "/");
			}
		} else {
			ERRLOG_INFO("Logon flag or state was 0, not redirecting");
		}

		/*
		 * If the cookiestore has some "values", we will include them into the request header
		 * ADD Headers into the backend request
		 */
		if (c->link_to_cookiestore != -1) {
			add_headers_into_request_from_cookiestore(r, c->link_to_cookiestore);
		}
		/*
		 * r->notes[REQUEST_COOKIES] now contains cookies from the cookiestore and all the
		 * free cookies copied from the original request by filter_cookie_request().
		 */
		const char *request_cookies = apr_table_get(r->notes, "REQUEST_COOKIES");
		if (request_cookies) {
			apr_table_set(r->headers_in, "Cookie", request_cookies);
		}

		/*
		 * Ok now we will proceed with the request
		 */
		ERRLOG_INFO("====== STOP ======");
		return OK;
	}

	/* this should never be reached */
	ERRLOG_CRIT("Fatal: unexpected end of function reached!");
	return HTTP_INTERNAL_SERVER_ERROR;
}


/*
 * Hook implementation to install the output filter.
 */
static void
mod_but_insert_output_filter(request_rec *r)
{
    ap_add_output_filter("MOD_BUT_OUT", NULL, r, r->connection);
}


/*
 * Performs per directory configuration during httpd startup phase
 * XXX fill in the defaults here instead of in _config.c
 */
static void *
mod_but_create_dir_conf(apr_pool_t *p, char *dummy)
{
	mod_but_dir_t *conf;
	conf = (mod_but_dir_t *)apr_pcalloc(p, sizeof(mod_but_dir_t));
	if (conf) {
		conf->logon_server_url = NULL;
	}
	return conf;
}


/*
 * Performs per server configuration during httpd startup phase
 * XXX fill in the defaults here instead of in _config.c
 */
static void *
mod_but_create_server_conf(apr_pool_t *p, server_rec *s)
{
	mod_but_server_t *conf;
	conf = (mod_but_server_t *)apr_pcalloc(p, sizeof(mod_but_server_t));
	if (conf) {
		conf->client_refuses_cookies_url = NULL;
		conf->cookie_name = NULL;
		conf->cookie_domain = NULL;
		conf->cookie_path = NULL;
		conf->cookie_expiration = NULL;
		conf->session_free_url = NULL;
	}
	return conf;
}


/*
 * The implementation of the configuration directive functions
 * is in mod_but_config.c.
 */
static const command_rec mod_but_cmds[] =
{
	/* global configuration */
	AP_INIT_FLAG( "MOD_BUT_ENABLED",                        mod_but_enabled_on,                         NULL, RSRC_CONF, "mod_but is enabled"),
	AP_INIT_TAKE1("MOD_BUT_CLIENT_REFUSES_COOKIES_URL",     mod_but_client_refuses_cookies,             NULL, RSRC_CONF, "Configure mod_but Redirect 3"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_NAME",                    mod_but_set_cookie_name,                    NULL, RSRC_CONF, "Configure mod_but Cookie Name"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_DOMAIN",                  mod_but_set_cookie_domain,                  NULL, RSRC_CONF, "Configure mod_but Cookie Domain"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_PATH",                    mod_but_set_cookie_path,                    NULL, RSRC_CONF, "Configure mod_but Cookie Path"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_EXPIRATION",              mod_but_set_cookie_expiration,              NULL, RSRC_CONF, "Configure mod_but Cookie Expiration Time"),
	AP_INIT_FLAG( "MOD_BUT_COOKIE_SECURE",                  mod_but_set_cookie_secure,                  NULL, RSRC_CONF, "Configure mod_but Cookie Secure Flag"),
	AP_INIT_FLAG( "MOD_BUT_COOKIE_HTTPONLY",                mod_but_set_cookie_httponly,                NULL, RSRC_CONF, "Configure mod_but HTTPOnly Flag"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_FREE_URL",               mod_but_set_session_free_url,               NULL, RSRC_CONF, "Configure mod_but free URL's"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_TIMEOUT",                mod_but_set_session_timeout,                NULL, RSRC_CONF, "Configure session timeout"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_HACKING_ATTEMPT_URL",    mod_but_set_session_hacking_attempt_url,    NULL, RSRC_CONF, "Configure session timeout URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_INACTIVITY_TIMEOUT",     mod_but_set_session_inactivity_timeout,     NULL, RSRC_CONF, "Configure session inactivity timeout"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL", mod_but_set_session_inactivity_timeout_url, NULL, RSRC_CONF, "Configure session inactivity timeout URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_TIMEOUT_URL",            mod_but_set_session_expired_url,            NULL, RSRC_CONF, "Configure session expired URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_RENEW_URL",              mod_but_set_session_renew_url,              NULL, RSRC_CONF, "Configure session renew URL"),
	AP_INIT_TAKE1("MOD_BUT_ALL_SHM_SPACE_USED_URL",         mod_but_set_all_shm_used_url,               NULL, RSRC_CONF, "Configure No more SHM URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_TIMEOUT_HISTORY",        mod_but_set_session_timeout_history,        NULL, RSRC_CONF, "Configure session timeout history"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_DESTROY",                mod_but_set_session_destroy,                NULL, RSRC_CONF, "Configure session destroy URI"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_DESTROY_URL",            mod_but_set_session_destroy_url,            NULL, RSRC_CONF, "Configure session destroy URL"),
	AP_INIT_FLAG( "MOD_BUT_AUTHORIZATION_ENABLED",          mod_but_authorization_enabled_on,           NULL, RSRC_CONF, "Authorization is enabled"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_SERVER_URL",        mod_but_global_logon_server_url,            NULL, RSRC_CONF, "Configure Global Logon Server URL"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_SERVER_URL_1",      mod_but_global_logon_server_url_1,          NULL, RSRC_CONF, "Configure Global Logon Server URL 1"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_SERVER_URL_2",      mod_but_global_logon_server_url_2,          NULL, RSRC_CONF, "Configure Global Logon Server URL 2"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_AUTH_COOKIE_NAME",  mod_but_global_logon_auth_cookie_name,      NULL, RSRC_CONF, "Configure Global Logon Cookie Name"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_AUTH_COOKIE_VALUE", mod_but_global_logon_auth_cookie_value,     NULL, RSRC_CONF, "Configure Global Logon Cookie Value"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_STORE_FREE_COOKIES",     mod_but_set_session_store_free_cookies,     NULL, RSRC_CONF, "Configure Cookies, which are not handled by the session store"),
	AP_INIT_TAKE1("MOD_BUT_SERVICE_LIST_COOKIE_NAME",       mod_but_set_service_list_cookie_name,       NULL, RSRC_CONF, "Configure Service List Cookie Name"),
	AP_INIT_TAKE1("MOD_BUT_SERVICE_LIST_COOKIE_VALUE",      mod_but_set_service_list_cookie_value,      NULL, RSRC_CONF, "Configure Cookies, which are not handled by the session store"),
	AP_INIT_TAKE1("MOD_BUT_SERVICE_LIST_AUTH_ERROR_URL",    mod_but_set_service_list_error_url,         NULL, RSRC_CONF, "Configure error page, if the user is not authorized for a specific request"),
	AP_INIT_FLAG( "MOD_BUT_SERVICE_LIST_ENABLED",           mod_but_service_list_enabled_on,            NULL, RSRC_CONF, "mod_but service list enabled"),
	AP_INIT_TAKE1("MOD_BUT_AUTHORIZED_LOGON_URL",           mod_but_set_authorized_logon_url,           NULL, RSRC_CONF, "Configure regexp url, from where you accept logon cookies"),
	/* per directory/location configuration */
	AP_INIT_TAKE1("MOD_BUT_LOGON_SERVER_URL", ap_set_string_slot, (void*)APR_OFFSETOF(mod_but_dir_t, logon_server_url),      OR_ALL, "Logon server relative URL for this directory"),
	AP_INIT_FLAG( "MOD_BUT_LOGON_REQUIRED",   ap_set_flag_slot,   (void*)APR_OFFSETOF(mod_but_dir_t, logon_required),        OR_ALL, "Logon requred for this directory?"),
	AP_INIT_TAKE1("MOD_BUT_LOCATION_ID",      ap_set_int_slot,    (void*)APR_OFFSETOF(mod_but_dir_t, mod_but_location_id),   OR_ALL, "Unique location ID for this directory"),
	AP_INIT_TAKE1("MOD_BUT_AUTH_STRENGTH",    ap_set_int_slot,    (void*)APR_OFFSETOF(mod_but_dir_t, mod_but_auth_strength), OR_ALL, "Authentication strength required for this directory"),
	{ NULL }
};


/*
 * Register additional hooks.
 */
static void
mod_but_register_hooks (apr_pool_t *p)
{
	static const char * const cfgPost[] = { "http_core.c", NULL };
	ap_hook_post_config(mod_but_shm_initialize, NULL, cfgPost, APR_HOOK_MIDDLE);
	ap_hook_post_config(mod_but_shm_initialize_history, NULL, cfgPost, APR_HOOK_MIDDLE);
	ap_hook_post_config(mod_but_shm_initialize_cookiestore, NULL, cfgPost, APR_HOOK_MIDDLE);
	ap_hook_access_checker(but_access, NULL, NULL, APR_HOOK_FIRST);

//	ap_register_input_filter("MOD_BUT_IN", mod_but_input_filter, NULL, AP_FTYPE_CONTENT_SET);
//	ap_hook_insert_filter(mod_but_insert_input_filter, NULL, NULL, APR_HOOK_FIRST);

	ap_register_output_filter("MOD_BUT_OUT", mod_but_output_filter, NULL, AP_FTYPE_CONTENT_SET);
	ap_hook_insert_filter(mod_but_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
}

/*
 * Declare mod_but module entry points.
 */
module AP_MODULE_DECLARE_DATA but_module =
{
	STANDARD20_MODULE_STUFF,	// standard Apache 2.0 module stuff
	mod_but_create_dir_conf,	// create per-directory configuration structures
	NULL,				// merge per-directory
	mod_but_create_server_conf,	// create per-server configuration structures
	NULL,				// merge per-server
	mod_but_cmds,			// configuration directive handlers
	mod_but_register_hooks,		// request handlers
};
