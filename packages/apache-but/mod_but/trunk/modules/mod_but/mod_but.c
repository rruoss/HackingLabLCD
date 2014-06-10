/* $Id: mod_but.c 147 2010-05-30 20:28:01Z ibuetler $ */

#include "mod_but.h"

/*
 * This is the main file for mod_but.  Code directly called from
 * Apache should be here.  All the Apache module API glue is here.
 * We have to ensure that we are compliant with the Apache API
 * specifications.  Helper functions called from here should in
 * general use apr_status_t error handling; those errors are
 * translated to specific HTTP error codes or redirections here.
 */

/* This mutex is used as a Giant-style global mutex to protect the shared memory
 * from corruption due to parallel access.  It must be acquired on in all hooks
 * which access the session store in any way and released before returning.
 * Failure to unlock will lead to Apache waiting for the lock forever.
 *
 * XXX Improve locking to allow for more parallelism.
 * This involves marking session slots busy during the time mod_but is doing it's
 * work, and only holding Giant while marking/unmarking slots as busy.
 */
apr_global_mutex_t *but_mutex;
char *mutex_filename;

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
but_output_filter(ap_filter_t *f, apr_bucket_brigade *bb_in)
{
	request_rec *r = f->r;
	mod_but_server_t *config;
	session_t session;
	cookie_res *cr;
	apr_status_t status;

	config = ap_get_module_config(r->server->module_config, &but_module);
	if (config == NULL) {
		ERRLOG_CRIT("Could not get configuration from apache");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (!config->enabled) {
		return ap_pass_brigade(f->next, bb_in);
	}

	if (apr_global_mutex_lock(but_mutex) != APR_SUCCESS) {
		ERRLOG_CRIT("Could not acquire mutex.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	but_session_init(&session, r, config);

	/* get session from request notes */
	{
		const char *indexstr = apr_table_get(r->notes, "BUTSESS");
		if (indexstr) {
/*OPEN*/		if (but_session_open(&session, atoi(indexstr)) != STATUS_OK) {
				apr_global_mutex_unlock(but_mutex);
				ERRLOG_CRIT("Session not found!");
				return HTTP_INTERNAL_SERVER_ERROR;
				/* XXX this may happen in some race conditions.  Handle gracefully. */
			}
		}
	}

	/*
	 * If no session was found for this response, then this is a free URL and
	 * we have no way to store cookies.  Skip cookie filtering.
	 */
	if (!but_session_isnull(&session)) {

		/*
		 * Do Header Parsing for all Set-Cookie Response Headers. We are looking for
		 * 	a) Session cookie
		 * 	b) Free cookies
		 * 	c) Service list cookies
		 * 	d) Other cookies
		 */
		cr = apr_pcalloc(r->pool, sizeof(cookie_res));
		if (!cr) {
			apr_global_mutex_unlock(but_mutex);
			ERRLOG_CRIT("Out of memory!");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		cr->r = r;
		cr->session = &session;
		cr->status = STATUS_OK;
		cr->headers = apr_table_make(r->pool, 0);
/*SET*/		apr_table_do(mod_but_filter_response_cookies_cb, cr, r->headers_out, "Set-Cookie", NULL);
		if (cr->status != STATUS_OK) {
			if (cr->status == STATUS_ESHMFULL) {
				status = mod_but_redirect_to_shm_error(r, config);
				apr_global_mutex_unlock(but_mutex);
				return status;
			}
			ERRLOG_CRIT("Error filtering the response cookies!");
			apr_global_mutex_unlock(but_mutex);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* Remove all Set-Cookie headers from response. */
		apr_table_unset(r->headers_out, "Set-Cookie");
		apr_table_unset(r->err_headers_out, "Set-Cookie");

		/* Add selected Set-Cookie headers back into r->headers_out. */
		apr_table_do(but_add_to_headers_out_cb, r, cr->headers, NULL);

		/*
		 * If iteration detected a valid LOGON=ok Set-Cookie header, cr->must_renew is set.
		 */
		if (cr->must_renew) {
			const char *session_handle_str;
			apr_status_t status;

			ERRLOG_INFO("=============================== START RENEW SESSION ====================================");
			ERRLOG_INFO("Renewing session after login.");
/*RENEW*/		status = but_session_renew(&session);
			if (status != STATUS_OK) {
				if (status == STATUS_ESHMFULL) {
					status = mod_but_redirect_to_shm_error(r, config);
					apr_global_mutex_unlock(but_mutex);
					return status;
				}
				apr_global_mutex_unlock(but_mutex);
				ERRLOG_INFO("Error renewing session");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			if (but_add_session_cookie_to_headers(r, config, r->headers_out, &session) != STATUS_OK) {
				apr_global_mutex_unlock(but_mutex);
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			/*
			 * renew_mod_but_session returned the new session index we have to update in r->notes.
			 */
			session_handle_str = apr_itoa(r->pool, session.handle);
			if (!session_handle_str) {
				apr_global_mutex_unlock(but_mutex);
				ERRLOG_CRIT("Out of memory!");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			apr_table_set(r->notes, "BUTSESS", session_handle_str);


			// REDIRECT TO MOD_BUT_REDIRECT IF ORIG_URL HANDLING IS DISABLED
	                if (!config->but_config_enabled_return_to_orig_url) {
                        	ERRLOG_INFO("REDIRECT TO ORIG URL IS DISABLED: REDIRECT TO MOD_BUT_REDIRECT [%s]", session.data->url);
				ERRLOG_INFO("Redirect to MOD_BUT_REDIRECT if LOGON=ok");
				r->status = mod_but_redirect_to_relurl(r, session.data->redirect_url_after_login);
			 }
		} /* must renew */
	} /* have session */

	apr_global_mutex_unlock(but_mutex);
	ap_remove_output_filter(f);
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
but_access_checker(request_rec *r)
{
	mod_but_dir_t *dconfig;
	mod_but_server_t *config;
	session_t session;
	cookie_res *cr;
	apr_status_t status;

	config = ap_get_module_config(r->server->module_config, &but_module);
	if (!config) {
		ERRLOG_CRIT("Could not get configuration from apache");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (!config->enabled) {
		ERRLOG_INFO("mod_but is not enabled, skip request (DECLINED)");
		return DECLINED;
	}

	/* get per-directory configuration */
	dconfig = ap_get_module_config(r->per_dir_config, &but_module);
	if (!dconfig) {
		ERRLOG_INFO("Illegal Directory Config");
	}

	if (apr_global_mutex_lock(but_mutex) != APR_SUCCESS) {
		ERRLOG_CRIT("Could not acquire mutex.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	but_session_init(&session, r, config);

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
/*CREATE*/	switch (but_session_create(&session)) {
		case STATUS_OK:
			/* session renewed, set cookie and redirect */
			if (but_add_session_cookie_to_headers(r, config, r->err_headers_out, &session) != STATUS_OK) {
				apr_global_mutex_unlock(but_mutex);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			status = mod_but_redirect_to_relurl(r, config->url_after_renew); /* XXX make configurable; default URL */
			apr_global_mutex_unlock(but_mutex);
			return status;
		case STATUS_ESHMFULL:
			status = mod_but_redirect_to_shm_error(r, config);
			apr_global_mutex_unlock(but_mutex);
			return status;
		case STATUS_ERROR:
		default:
			apr_global_mutex_unlock(but_mutex);
			ERRLOG_CRIT("Error creating new session");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		break; /* not reached */

	case STATUS_NOMATCH:
		/* do nothing */
		break;

	case STATUS_ERROR:
	default:
		apr_global_mutex_unlock(but_mutex);
		ERRLOG_CRIT("Error while matching MOD_BUT_SESSION_RENEW_URL");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * Session free URL?
	 */
	switch (mod_but_regexp_match(r, config->session_free_url, r->uri)) {
	case STATUS_MATCH:
		apr_global_mutex_unlock(but_mutex);
		ERRLOG_INFO("Session free URL [%s]", r->uri);
		return DECLINED;

	case STATUS_NOMATCH:
		/* do nothing */
		break;

	case STATUS_ERROR:
	default:
		apr_global_mutex_unlock(but_mutex);
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

	/*
	 * iterate over all Cookie headers and unset them;
	 * cookies for backend are now in r->notes
	 */
	cr = apr_pcalloc(r->pool, sizeof(cookie_res));
	if (!cr) {
		apr_global_mutex_unlock(but_mutex);
		ERRLOG_CRIT("Out of memory!");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	cr->r = r;
	cr->status = STATUS_OK;
	cr->headers = apr_table_make(r->pool, 0);
	apr_table_do(mod_but_filter_request_cookies_cb, cr, r->headers_in, "Cookie", NULL);
	if (cr->status != STATUS_OK) {
		apr_global_mutex_unlock(but_mutex);
		ERRLOG_CRIT("Error while iterating Cookie headers.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	apr_table_unset(r->headers_in, "Cookie");

	ERRLOG_INFO("Session ID [%s]", cr->sessionid);

	/*
	 * If the client has sent no session cookie, create a new session
	 * and redirect to cookie try.
	 */
	if (!cr->sessionid) {
		ERRLOG_INFO("Client did not send mod_but session");
/*CREATE*/	switch (but_session_create(&session)) {
		case STATUS_OK:
			/* session created, set cookie and redirect */
			if (but_add_session_cookie_to_headers(r, config, r->err_headers_out, &session) != STATUS_OK) {
				apr_global_mutex_unlock(but_mutex);
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			status = mod_but_redirect_to_cookie_try(r, config);
			apr_global_mutex_unlock(but_mutex);
			return status;
		case STATUS_ESHMFULL:
			status = mod_but_redirect_to_shm_error(r, config);
			apr_global_mutex_unlock(but_mutex);
			return status;
		case STATUS_ERROR:
		default:
			apr_global_mutex_unlock(but_mutex);
			ERRLOG_CRIT("Error creating new session");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		/* not reached */
	}

	/*
	 * The client has sent a session (valid or invalid)
	 */

	/* Initialize the session struct. */
	but_session_init(&session, r, config);

	/* Look up the session. */
/*FIND*/switch (but_session_find(&session, config->cookie_name, cr->sessionid)) {
	case STATUS_OK:
		break;

	case STATUS_ENOEXIST:
		/* session not found */
		ERRLOG_INFO("Session timed out or invalid");
		if (!config->session_expired_url) {
			apr_global_mutex_unlock(but_mutex);
			ERRLOG_INFO("MOD_BUT_SESSION_TIMEOUT_URL not configured");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		status = mod_but_redirect_to_relurl(r, config->session_expired_url);
		apr_global_mutex_unlock(but_mutex);
		return status;

	case STATUS_ERROR:
	default:
		apr_global_mutex_unlock(but_mutex);
		ERRLOG_CRIT("Error finding session!");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Validate the session, time it out if necessary, updating atime. */
/*UNLINK,SET*/switch (but_session_validate(&session,
			config->session_hard_timeout,
			config->session_inactivity_timeout)) {
	case STATUS_OK:
		break;

	case STATUS_ENOEXIST:
		/* the sent session has reached its hard or soft timeout */
		ERRLOG_INFO("Session timed out.");
		if (!config->session_expired_url) {
			apr_global_mutex_unlock(but_mutex);
			ERRLOG_INFO("MOD_BUT_SESSION_TIMEOUT_URL not configured");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		status = mod_but_redirect_to_relurl(r, config->session_expired_url);
		apr_global_mutex_unlock(but_mutex);
		return status;

	case STATUS_ERROR:
	default:
		apr_global_mutex_unlock(but_mutex);
		ERRLOG_CRIT("Error validating session!");
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
		ERRLOG_INFO("Session destroy URL matched, destroying session");
/*UNLINK*/	but_session_unlink(&session);
		status = mod_but_redirect_to_relurl(r, config->session_destroy_url);
		apr_global_mutex_unlock(but_mutex);
		return status;

	case STATUS_NOMATCH:
		ERRLOG_INFO("r->uri does not match session destroy URL [%s]", r->uri);
		break;

	case STATUS_ERROR:
	default:
		apr_global_mutex_unlock(but_mutex);
		ERRLOG_CRIT("Error matching session destroy URL");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * If we are here, the requesting URL does not want to be destroyed and we analyze
	 * the request for the cookie_try.  If we are still in the cookie test phase, we
	 * have to give the client the Original URI (from the first request) as redirect
	 */

	/* store session index into request notes for output filter to process */
	{
		const char *session_index_str = apr_itoa(r->pool, session.handle);
		if (!session_index_str) {
			apr_global_mutex_unlock(but_mutex);
			ERRLOG_INFO("Out of memory!");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		ERRLOG_INFO("Setting r->notes[BUTSESS] to [%s]", session_index_str);
		apr_table_set(r->notes, "BUTSESS", session_index_str);
	}

	/*
	 * Cookie is sent by the client, it is a valid session and the
	 * requesting URL contains the cookie_try parameter.
	 * session.data->url was set before redirecting to cookie_try.
	 */
	if (mod_but_find_cookie_try(r) > 0) {
/*GET*/		if (!apr_strnatcmp(session.data->url, "empty")) {
			apr_global_mutex_unlock(but_mutex);
			ERRLOG_CRIT("Session contains no URL!");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		ERRLOG_INFO("Client session is valid and cookie test succeeded");
/*GET*/		status = mod_but_redirect_to_relurl(r, session.data->url);
		apr_global_mutex_unlock(but_mutex);
		return status;
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
/*GET*/		switch (but_access_control(r, &session, config, dconfig)) {
		case STATUS_ELOGIN:
			ERRLOG_INFO("URI requires auth, but user not logged in yet [%s]", r->unparsed_uri);
			/* use r->unparsed_uri instead of r->uri to safeguard against HTTP Response Splitting */
/*SET*/			apr_cpystrn(session.data->url, r->unparsed_uri, sizeof(session.data->url));
			ERRLOG_INFO("Storing original URL before logon [%s]", session.data->url);
/*SET*/			session.data->redirect_on_auth_flag = 1;
			ERRLOG_INFO("Setting redirect on auth flag to [%d]", session.data->redirect_on_auth_flag);

			if (dconfig->logon_server_url) {
				/* login server is configured for this Location */
				status = mod_but_redirect_to_relurl(r, dconfig->logon_server_url);
				apr_global_mutex_unlock(but_mutex);
				return status;
			} else {
				/* No login server is configured for this Location */
				if (!config->global_logon_server_url) {
					apr_global_mutex_unlock(but_mutex);
					ERRLOG_CRIT("Global logon server URL is not set");
					return HTTP_INTERNAL_SERVER_ERROR;
				}
				status = mod_but_redirect_to_relurl(r, config->global_logon_server_url);
				apr_global_mutex_unlock(but_mutex);
				return status;
			}
			break; /* not reached */

		case STATUS_OK:
			ERRLOG_INFO("client is sufficiently authorized or no auth required");
			break;

		case STATUS_EDENIED:
			ERRLOG_CRIT("Client authenticated but not authorized for this URL");
			if (!config->service_list_error_url) {
				apr_global_mutex_unlock(but_mutex);
				ERRLOG_CRIT("Service list error URL not set");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			status = mod_but_redirect_to_relurl(r, config->service_list_error_url);
			apr_global_mutex_unlock(but_mutex);
			return status;

		case STATUS_ESTEPUP1:
			ERRLOG_INFO("Client authenticated but auth_strength too low for this URL");
			if (!config->global_logon_server_url_1) {
				apr_global_mutex_unlock(but_mutex);
				ERRLOG_CRIT("Gobal logon server URL 1 not set");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			/* use r->unparsed_uri instead of r->uri to safeguard against HTTP Response Splitting */
/*SET*/			apr_cpystrn(session.data->url, r->unparsed_uri, sizeof(session.data->url));
			ERRLOG_INFO("Storing original URL before logon [%s]", session.data->url);
/*SET*/			session.data->redirect_on_auth_flag = 1;
			ERRLOG_INFO("Setting redirect on auth flag to [%d]", session.data->redirect_on_auth_flag);
			status = mod_but_redirect_to_relurl(r, config->global_logon_server_url_1);
			apr_global_mutex_unlock(but_mutex);
			return status;

		case STATUS_ESTEPUP2:
			ERRLOG_INFO("Client authenticated but auth_strength too low for this URL");
			if (!config->global_logon_server_url_2) {
				apr_global_mutex_unlock(but_mutex);
				ERRLOG_CRIT("Global logon server URL 2 not set");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			/* use r->unparsed_uri instead of r->uri to safeguard against HTTP Response Splitting */
/*SET*/			apr_cpystrn(session.data->url, r->unparsed_uri, sizeof(session.data->url));
			ERRLOG_INFO("Storing original URL before logon [%s]", session.data->url);
/*SET*/			session.data->redirect_on_auth_flag = 1;
			ERRLOG_INFO("Setting redirect on auth flag to [%d]", session.data->redirect_on_auth_flag);
			status = mod_but_redirect_to_relurl(r, config->global_logon_server_url_2);
			apr_global_mutex_unlock(but_mutex);
			return status;

		case STATUS_ERROR:
		default:
			apr_global_mutex_unlock(but_mutex);
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
	 * This is the redirection to the original protected URL function after login.
	 * If the user was successfully authenticated and the session_data->redirect_on_auth_flag is 1,
	 * we need to redirect the user to his original URL or / if none was found.
	 * That can happen when the user directly enters the site on the login URL.
	 */
	ERRLOG_INFO("Redirect on auth flag [%d] logon state [%d]", session.data->redirect_on_auth_flag, session.data->logon_state);
/*GET*/	if (session.data->redirect_on_auth_flag == 1 && session.data->logon_state == 1) {
/*SET*/		session.data->redirect_on_auth_flag = 0;

                if (config->but_config_enabled_return_to_orig_url) {
			ERRLOG_INFO("REDIRECT TO ORIG URL IS ENABLED: Redirect to [%s]", session.data->url);
/*GET*/			if (!apr_strnatcmp(session.data->url, "empty")) {
				ERRLOG_INFO("============ REDIRECT TO [/] because orig_url was empty ");
				status = mod_but_redirect_to_relurl(r, "/");
				/* XXX make URL configurable: default rel URL */
				apr_global_mutex_unlock(but_mutex);
				return status;
			} else {
				ERRLOG_INFO("============ REDIRECT TO [%s] to orig_url", session.data->url);
/*GET*/				status = mod_but_redirect_to_relurl(r, session.data->url);
				apr_global_mutex_unlock(but_mutex);
				return status;
			}
                } else {
                        ERRLOG_INFO("REDIRECT TO ORIG URL IS DISABLED: Redirect to = [%s]", session.data->redirect_url_after_login);
/*GET*/                 //status = mod_but_redirect_to_relurl(r, session.data->redirect_url_after_login);
                        //apr_global_mutex_unlock(but_mutex);
                        //return status;
                }
		
	} else {
		ERRLOG_INFO("Logon state or redirect on auth flag was 0, not redirecting");
	}





	/* Add cookies from cookie store to request headers. */
/*GET*/	if (session.data->cookiestore_index != -1) {
/*GET*/		const char *cookie = but_session_get_cookies(&session);
		if (cookie) {
			apr_table_set(r->headers_in, "Cookie", cookie);
		}
	}

	apr_global_mutex_unlock(but_mutex);

	/* Add selected Cookie headers back into r->headers_in. */
	apr_table_do(but_add_to_headers_in_cb, r, cr->headers, NULL);

	/* Hand request down to the next module. */
	return OK;
}

/*
 * This callback is called when the parent initialized.
 * Note that this can happen multiple times.
 */
static int but_post_config(apr_pool_t *pconf, apr_pool_t *plog,
                             apr_pool_t *ptemp, server_rec *s)
{
	void *data;
	const char *userdata_key = "but_init_module";
	apr_status_t status;

	/* 
	 * The following checks if this routine has been called before.
	 * This is necessary because the parent process gets initialized
	 * a couple of times as the server starts up, and we don't want
	 * to create any more mutexes and shared memory segments than
	 * we're actually going to use.
	 */ 
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (!data) {
		apr_pool_userdata_set((const void *) 1, userdata_key,
			apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	/* Create the shared memory segments. */
	status = but_shm_initialize(pconf, plog, ptemp, s);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_CRIT("Failed to initialize session SHM.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	status = but_shm_initialize_cookiestore(pconf, plog, ptemp, s);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_CRIT("Failed to initialize cookiestore SHM.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* Create the module mutex. */

	/*
	 * Create another unique filename to lock upon. Note that
	 * depending on OS and locking mechanism of choice, the file
	 * may or may not be actually created. 
	 */
	status = apr_global_mutex_create(&but_mutex, tmpnam(NULL), APR_LOCK_DEFAULT, pconf);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_CRIT("Failed to create mutex.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

#ifdef MOD_BUT_SET_MUTEX_PERMS
	status = ap_unixd_set_global_mutex_perms(but_mutex);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_CRIT("Failed to set mutex permissions.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
#endif /* MOD_BUT_SET_MUTEX_PERMS */

	return OK;
}

/*
 * This callback is called when a child process initializes.
 * We use it to set up the mutex.
 */
static void
but_child_init(apr_pool_t *p, server_rec *s)
{
	apr_status_t status;

	/* Re-open the mutex in the child process. */
	status = apr_global_mutex_child_init(&but_mutex, (const char*) mutex_filename, p);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_CRIT("Failed to reopen mutex on file %s", mutex_filename);
		exit(1);
	}
}


/*
 * Hook implementation to install the output filter.
 */
static void
but_insert_output_filter(request_rec *r)
{
	ap_add_output_filter("MOD_BUT_OUT", NULL, r, r->connection);
}


/*
 * Performs per directory configuration during httpd startup phase
 * XXX fill in the defaults here instead of in _config.c
 */
static void *
but_create_dir_conf(apr_pool_t *p, char *dummy)
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
but_create_server_conf(apr_pool_t *p, server_rec *s)
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
 * Register additional hooks.
 */
static void
but_register_hooks(apr_pool_t *p)
{
	static const char * const cfgPost[] = { "http_core.c", NULL };

	ap_hook_post_config(but_post_config, NULL, cfgPost, APR_HOOK_MIDDLE);
	ap_hook_child_init(but_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_access_checker(but_access_checker, NULL, NULL, APR_HOOK_FIRST);

#if 0
	ap_register_input_filter("MOD_BUT_IN", mod_but_input_filter, NULL, AP_FTYPE_CONTENT_SET);
	ap_hook_insert_filter(mod_but_insert_input_filter, NULL, NULL, APR_HOOK_FIRST);
#endif

	ap_register_output_filter("MOD_BUT_OUT", but_output_filter, NULL, AP_FTYPE_CONTENT_SET);
	ap_hook_insert_filter(but_insert_output_filter, NULL, NULL, APR_HOOK_LAST);
}

/*
 * Declare mod_but module entry points.
 */
module AP_MODULE_DECLARE_DATA but_module =
{
	STANDARD20_MODULE_STUFF,	/* standard Apache 2.0 module stuff              */
	but_create_dir_conf,		/* create per-directory configuration structures */
	NULL,				/* merge per-directory                           */
	but_create_server_conf,		/* create per-server configuration structures    */
	NULL,				/* merge per-server                              */
	but_cmds,			/* configuration directive handlers              */
	but_register_hooks,		/* request handlers                              */
};


