/*#############################################
#
# Title:        mod_but.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/


#include "mod_but.h"


static void mod_but_insert_output_filter(request_rec *r)
{
    ap_add_output_filter("MOD_BUT_OUT", NULL, r, r->connection);
}


/*
	This function parses the http-response headers from a backend system. 
	We want to find out if the response-header has a
	a) Set-Cookie header which should be stored to the session store
	b) Set-Cookie header which is configured as "free" cookie
	c) Set-Cookie header which has a special meaning to us (Auth=ok)
*/
static apr_status_t mod_but_output_filter(ap_filter_t *f, apr_bucket_brigade *bb_in)
{
	apr_int64_t i;
	int shmoffsetnew;
	char *pshm_offset_number;

	apr_port_t port = 0;
	char *host = NULL;
	char *all_shm_space_used_url = NULL;
	const char *protocol, *ssl_session_id, *ssl_cipher;

	request_rec *r = f->r;
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	cookie_res *cr = apr_palloc(r->pool, sizeof(cookie_res));
        cr->r = r;
        cr->cookie = NULL;

	apr_int64_t num_set_cookie;

	port = ap_get_server_port (r);
	if ((port != 80) && (port != 443)) {
	/* because of multiple passes through don't use r->hostname() */
		host = (char *)apr_psprintf(r->pool, "%s:%d", ap_get_server_name (r), port);
	} else {
		host = (char *)apr_psprintf(r->pool, "%s", ap_get_server_name (r));
	}

	protocol = (char *)ssl_var_lookup(r->pool, r->server, r->connection, r, apr_pstrdup(r->pool, "SSL_PROTOCOL") );
    	ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: SSL_PROTOCOL [%s]", protocol);

    	ssl_session_id = (char *)ssl_var_lookup(r->pool, r->server, r->connection, r, apr_pstrdup(r->pool, "SSL_SESSION_ID") );
    	ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: SSL_SESSION_ID [%s]", ssl_session_id);

    	ssl_cipher = (char *)ssl_var_lookup(r->pool, r->server, r->connection, r, apr_pstrdup(r->pool, "SSL_CIPHER") );
    	ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: SSL_CIPHER [%s]", ssl_cipher);



	/*
		This checks if the response has a Set-Cookie set. There could be

			a) NO Set-Cookie in response-header
			b) LOGON Set-Cookie in response-header
			c) FREE COOKIE in response-header
			d) Other's Cookies in response-header (belonging into session store)

	*/
	

	ap_log_rerror(PC_LOG_INFO, r, "mod_but: Calling apr_table_do(mod_but_analyze_response_headers)");

	


	/*
		Do Header Parsing for all Response Headers. We are looking for

		a) MOD_BUT SESSION
		b) FREE COOKIES
		c) SERVICE_LIST COOKIES
		d) OTHER COOKIES	
	*/	
	apr_table_set(r->notes, "NUM_SET_COOKIE", "0");
	apr_table_do(mod_but_analyze_response_headers, cr, r->headers_out, NULL);
	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED MOD_BUT_ANALYZE_RESPONSE_HEADER");


	/*
		Unsetting all Set-Cookie Headers from Response (All but MOD_BUT_SESSION)
	*/
	apr_table_unset(r->headers_out, "Set-Cookie");
	apr_table_unset(r->err_headers_out, "Set-Cookie");
	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: P1: UNSETTING ALL RESPONSE HEADERS");

	/*
		Setting FREE Cookies into the Response Header manually
	*/
	num_set_cookie = apr_atoi64(apr_table_get(r->notes, "NUM_SET_COOKIE"));
	for (i = 1; i <= num_set_cookie; i++) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: FOR LOOP -- NUM_SET_COOKIE IS [%s]", apr_table_get(r->notes, "NUM_SET_COOKIE"));
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: VALUE IS [%s]", apr_table_get(r->notes, apr_itoa(r->pool, i)));
		apr_table_set(r->headers_out, "Set-Cookie", apr_table_get(r->notes, apr_itoa(r->pool, i)));
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: P2: SETTING FREE COOKIES INTO THE RESPONSE");
	}


	/*
		If apr_table_do detected a LOGON=ok Set-Cookie Header, There will be a r->notes about it. Otherwise
		r->notes is empty.
	*/
	if (apr_table_get(r->notes, "LOGON_STATUS") != NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: LOGON STATUS = [%s]", apr_table_get(r->notes, "LOGON_STATUS"));
		i = apr_atoi64(apr_table_get(r->notes, "SHMOFFSET"));
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: VOR renew_mod_but_session in mod_but.c");
		shmoffsetnew = renew_mod_but_session(i, r);

		if (shmoffsetnew == -1)
		{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with SHM Creation, DECLINED");
			apr_table_unset(r->headers_out, "Set-Cookie");
			apr_table_unset(r->err_headers_out, "Set-Cookie");

			if (apr_strnatcmp(ssl_session_id,"")){
				all_shm_space_used_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->all_shm_space_used_url );
			} else {
				all_shm_space_used_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->all_shm_space_used_url );
			}	
			apr_table_setn(r->err_headers_out, "Location", all_shm_space_used_url);
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED ALL_SHM_SPACE_USED");
			r->content_type = NULL;
			return OK;
		}

		if (shmoffsetnew == -2)
		{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with SID Creation, DECLINED");
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: END OF OUTPUT FILTER");
			//return 2400;
			return OK;
		}

		ap_log_rerror(PC_LOG_INFO, r, "mod_but: OUTPUT FILTER: SHMOFFSET BEFORE [%s]", apr_table_get(r->notes, "SHMOFFSET"));

		/*
			This is the runtime fix, so that the other stuff will have the correct SHMOFFSET.
			renew_mod_but_session returned the new SHMOFFST we have to put into r->notes
		*/
		pshm_offset_number = apr_itoa(r->pool, shmoffsetnew);
		apr_table_set(r->notes, "SHMOFFSET", pshm_offset_number);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: END OF OUTPUT FILTER");
	}

	if (apr_table_get(r->notes, "CS_SHM") != NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with SHM Cookie Store - ALERT - No space left in SHM Cookiestore to include a processing header");
	}

	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: P3: BEFORE REMOVE OUTPUT FILTER");
        ap_remove_output_filter(f);
	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: P4: AFTER REMOVE OUTPUT FILTER & BEFORE AP_PASS_BRIGADE");
        return ap_pass_brigade(f->next, bb_in);
}

/*	
	This is the most important function in mod_but. It is the core for handling
	requests from the Internet client. It implements:

	a) MOD_BUT session is required for the requesting  URL
	if a) is true
		a1) Check if the user is sending a MOD_BUT session
		a2) If an invalid session is sent -> redirect client to error page
		a3) If no session is sent -> create new session and go ahead
		a4) If an old session is sent -> redirect client ot error page

		a5) If the client is sending some "free" cookies
		
	
	if a) is false
		b1) Check 
*/

static int but_access(request_rec *r)
{

       // pcre (is session free url)
	   pcre *re = NULL;  					// the regular expression
       const char *error;				// error text for the failed regex compilation
       int error_offset;				// offset of the regex compilation error, if any
       int rc = 0;					// return code of pcre_exec
	   int re_vector[3072];
	   
	   // pcre (session_renew in url)
	   pcre *re6 = NULL;  					// the regular expression
       const char *error6;				// error text for the failed regex compilation
       int error_offset6;				// offset of the regex compilation error, if any
       int rc6 = 0;					// return code of pcre_exec
	   int re_vector6[3072];
	   
	   // firsturl pcre
       pcre *re4 = NULL;  					// the regular expression
       const char *error4;				// error text for the failed regex compilation
       int error_offset4;				// offset of the regex compilation error, if any
       int rc4 = 0;					// return code of pcre_exec
       int re_vector4[3072];

	   //firsturl pcre
       pcre *re5 = NULL;  					// the regular expression
       //const char *error5;				// error text for the failed regex compilation
       //int error_offset5;				// offset of the regex compilation error, if any
       int rc5 = 0;					// return code of pcre_exec
       int re_vector5[3072];
	   


	   // rc = return codes
       static int rc1 = 0;
       apr_status_t rc2 = 0;
       static int rc3 = 0;
	   
	   
	   // shared memory settings
       int shmoffset = 0;
       static apr_rmm_t *cs_rmm = NULL;
       static apr_rmm_off_t *off = NULL;
       cookie_res *cr;
	   
	   // configuration mod_but
       const char *cookie_try;
       char *pshm_offset_number;
       mod_but_cookie *c;
       mod_but_dir_t *dconfig;
       apr_port_t port = 0;
       char *host = NULL;
       char *no_cookie_support_url = NULL;
       char *session_destroy_url = NULL;
       char *all_shm_space_used_url = NULL;
       char *default_url = NULL;
       char *session_expired_url = NULL;
       char *session_inactivity_timeout_url = NULL;
       char *session_firsturl = NULL;
       char *logon_server_url = NULL;
       char *global_logon_server_url = NULL;
       char *global_logon_server_url_1 = NULL;
       char *global_logon_server_url_2 = NULL;
       char *service_list_error_url = NULL;
       char *orig_url_before_logon = NULL;
       char *session_hacking_attempt_url = NULL;





       ap_log_rerror(PC_LOG_CRIT, r, "mod_but: START");
       const char *protocol, *ssl_session_id, *ssl_cipher;

       mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
       if (config == NULL) {
       		return (int)apr_pstrcat(r->pool, "Illegal server record", NULL, NULL);
		}

	// get per-directory configuration
	dconfig = ap_get_module_config(r->per_dir_config, &but_module);
	if (dconfig == NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: Illegal Directory Config");
	}

    if (!config->enabled) {
    	ap_log_rerror(PC_LOG_INFO, r, "mod_but: mod_but_enabled is not activated");
        return DECLINED;
    }

    ap_log_rerror(PC_LOG_INFO, r, "mod_but: ========= START V1.0 =========== mod_but hook is executed by apache core");
    ap_log_rerror(PC_LOG_INFO, r, "mod_but: Request %s", r->uri);


	port = ap_get_server_port (r);
	if ((port != 80) && (port != 443)) {
	/* because of multiple passes through don't use r->hostname() */
		host = (char *)apr_psprintf(r->pool, "%s:%d", ap_get_server_name (r), port);
	} else {
		host = (char *)apr_psprintf(r->pool, "%s", ap_get_server_name (r));
	}

	protocol = (char *)ssl_var_lookup(r->pool, r->server, r->connection, r, apr_pstrdup(r->pool, "SSL_PROTOCOL") );
    	ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: SSL_PROTOCOL [%s]", protocol);

    	ssl_session_id = (char *)ssl_var_lookup(r->pool, r->server, r->connection, r, apr_pstrdup(r->pool, "SSL_SESSION_ID") );
    	ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: SSL_SESSION_ID [%s]", ssl_session_id);

    	ssl_cipher = (char *)ssl_var_lookup(r->pool, r->server, r->connection, r, apr_pstrdup(r->pool, "SSL_CIPHER") );
    	ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: SSL_CIPHER [%s]", ssl_cipher);

    /****************************** PART 1 *******************************************************

    		Check if mod_but session is required for the requesting URI

    */




    /*

    	The var session_free_url implements a regexp for all URL's, for which mod_but does not require a valid session
    */
    if(config->session_free_url != NULL){
    	re = pcre_compile(config->session_free_url, 0, &error, &error_offset, NULL);
    }else{
	ap_log_rerror(PC_LOG_INFO, r, "mod_but: PCRE FREE URL STRING IS NULL");
    }


    if (re == NULL) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: return code of pcre_compile is NULL");
    }

    rc = pcre_exec(re, NULL, r->uri, strlen(r->uri), 0, 0, re_vector, 3072);

	// BUT-0: session required (goto BUT-1)
    if (rc < 0 && rc != PCRE_ERROR_NOMATCH) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: %s ID is required for this URI = %s", config->cookie_name, r->uri);
    }

    if (rc == 0) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: PCRE output vector too small (%d)", 3072/3-1);
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with the following URI = %s", r->uri);
	return DECLINED;
    }

	
	// session not required
    if (rc > 0) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: SESSION FREE URL [%s] - [%s]", config->cookie_name, r->uri);

	/*

		Renew Session if in URI is defined as RENEW_URI
	*/
	if(config->session_renew_url != NULL){
		re6 = pcre_compile(config->session_renew_url, 0, &error6, &error_offset6, NULL);
	}else{
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: PCRE FREE URL STRING IS NULL");
	}


	if (re6 == NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: return code of pcre_compile is NULL");
	}

	rc6 = pcre_exec(re6, NULL, r->uri, strlen(r->uri), 0, 0, re_vector6, 3072);

	if (rc6 < 0 && rc6 != PCRE_ERROR_NOMATCH) {
		// renew url not found
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: Renew URL is not called");
	}

	if (rc6 == 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: PCRE output vector too small (%d)", 3072/3-1);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with the following URI = %s", r->uri);
		return DECLINED;
	}

	if (rc6 > 0) {
		// renew url found!!
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: RENEW SESSION, because RENEW URL [%s] - [%s]", config->cookie_name, r->uri);
		shmoffset = create_new_mod_but_session(r);
		if (shmoffset == -1)
		{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with SHM Creation, DECLINED");
			if (config->all_shm_space_used_url == NULL ){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: MOD_BUT_ALL_SHM_SPACE_USED_URL not configured in httpd.conf");
				return HTTP_INTERNAL_SERVER_ERROR;
			}

			if (apr_strnatcmp(ssl_session_id,"")){
				all_shm_space_used_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->all_shm_space_used_url );
			} else {
				all_shm_space_used_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->all_shm_space_used_url );
			}
			apr_table_setn(r->err_headers_out, "Location", all_shm_space_used_url);
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED ALL_SHM_SPACE_USED_URL");
			r->content_type = NULL;
			return HTTP_MOVED_TEMPORARILY;
		}

		if (shmoffset == -2)
		{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with SID Creation, DECLINED");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (apr_strnatcmp(ssl_session_id,"")){
			default_url = (char *)apr_psprintf(r->pool, "https://%s/", host);
		} else {
			default_url = (char *)apr_psprintf(r->pool, "http://%s/", host);
		}

		apr_table_setn(r->err_headers_out, "Location", default_url);
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED DEFAULT_URL");
		r->content_type = NULL;
		return HTTP_MOVED_TEMPORARILY;
	}

	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED RENEW URL");
        return DECLINED;
    }




    /****************************** PART 2 *******************************************************

    		Check of the mod_but session

			a) mod_but session is not sent by client
			b) mod_but session sent is invalid
			c) mod_but session sent is ok

		The code below will only be executed, if the requesting URI requires a mod_but session (status regexp < 0)


    */




	/*
		BUT-1 (comming from BUT-0) -> session is required
		Here we will first parse the request headers for
		
		a) MOD_BUT_SESSION (will be unset, because we don't want to have it in the backend)
		b) FREE COOKIES (will be accepted, if configured in httpd.conf)
		c) OTHER COOKIES (will be unset)
	*/

	if (apr_table_get(r->notes, config->cookie_name)) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: GET SESSION FROM r->notes [%s]", apr_table_get(r->notes, config->cookie_name));
	} else {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: DO INITIAL HEADER PARSING r->notes [%s]", apr_table_get(r->notes, config->cookie_name));
		cr = apr_palloc(r->pool, sizeof(cookie_res));
		cr->r = r;
		cr->cookie = NULL;
		apr_table_do(mod_but_analyze_request_headers, cr, r->headers_in, NULL);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: mod_but_analyze_request_headers finished");
	}


       ap_log_rerror(PC_LOG_INFO, r, "mod_but: SESSION [%s]", apr_table_get(r->notes, config->cookie_name));

       if (apr_table_get(r->notes, config->cookie_name) == NULL) {

       /*
       		This is PART 2  a) mod_but session is not sent by client
       */
       		ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE: CLIENT DID NOT SEND MOD_BUT_SESSION)");
		shmoffset = create_new_mod_but_session(r);
		if (shmoffset == -1)
		{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with SHM Creation, DECLINED");
                        if (config->all_shm_space_used_url == NULL ){
                                ap_log_rerror(PC_LOG_INFO, r, "mod_but: MOD_BUT_ALL_SHM_SPACE_USED_URL not configured in httpd.conf");
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }

			if (apr_strnatcmp(ssl_session_id,"")){
				all_shm_space_used_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->all_shm_space_used_url );
			} else {
				all_shm_space_used_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->all_shm_space_used_url );
			}
			apr_table_setn(r->err_headers_out, "Location", all_shm_space_used_url);
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED ALL_SHM_SPACE_USED_URL");
			r->content_type = NULL;
	    		return HTTP_MOVED_TEMPORARILY;
		}

		if (shmoffset == -2)
		{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with SID Creation, DECLINED");
			return HTTP_INTERNAL_SERVER_ERROR;
		}



	/*
		If client did not send a MOD_BUT session


		return code rc1 of analyze_request_arguments_for_cookie_test(r)
			9900: first client request without __cookie_try in query
			9901: second client request with __cookie_try=1 in query
			9902: third client request with __cookie_try=2 in query
			9903: fouth client request with __cookie_try=3 in query, Redirect to error page
			9904: DECLINED

	*/

	    rc1 = analyze_request_arguments_for_cookie_test(r);
	    ap_log_rerror(PC_LOG_CRIT, r, "mod_but: RETURN VALUE OF COOKIE_TEST ROUTINE %d", rc1);
	    cookie_try = NULL;

            ap_log_rerror(PC_LOG_INFO, r, "mod_but: rc1 is %d", rc1);

	// NO COOKIE_TRY in URL


	    if (rc1 == 9900){
                ap_log_rerror(PC_LOG_INFO, r, "mod_but: rc1 = 9900 aufgerufen");
		//TODO BUT: Use absolute URI for redirection

    re5 = pcre_compile("\r\n", 0, &error4, &error_offset4, NULL);

    if (re5 == NULL) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: return code of pcre_compile is NULL");
    }

    rc5 = pcre_exec(re5, NULL, r->uri, strlen(r->uri), 0, 0, re_vector5, 3072);

    if (rc5 < 0) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: r->uri does not contain CR/LF [%s]", r->uri);
		if (apr_strnatcmp(ssl_session_id,"")){
			cookie_try = (char *)apr_psprintf(r->pool, "https://%s%s?__cookie_try=1", host, r->uri); // uri starts with a "/"
		} else {
			cookie_try = (char *)apr_psprintf(r->pool, "http://%s%s?__cookie_try=1", host, r->uri); // uri starts with a "/"
		}
                apr_table_setn(r->err_headers_out, "Location", cookie_try);
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED COOKIE_TRY; CLIENT SENT R WITHOUT SESSION; REDIRECT TO COOKIE_TRY");
            	r->content_type = NULL;
	    	return HTTP_MOVED_TEMPORARILY;
    }

    if (rc5 < 0 && rc5 != PCRE_ERROR_NOMATCH) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: r->uri does not contain CR/LF [%s]", r->uri);
    }

    if (rc5 == 0) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: PCRE output vector too small (%d)", 3072/3-1);
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with pcre CRLF = %s", r->uri);
	return DECLINED;
    }

	if (rc5 > 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: ATTACK!!!! r->uri contains CR/LF [%s]", r->uri);
		apr_table_setn(r->err_headers_out, "Location", "file:///C:\\<script>alert('Hacking?')</script>");
		r->content_type = NULL;
		return HTTP_MOVED_TEMPORARILY;
	}



	    }


	// 1 COOKIE_TRY in URL
            if (rc1 == 9901){
                ap_log_rerror(PC_LOG_INFO, r, "mod_but: rc1 = 9901 aufgerufen");
		//TODO BUT: Use absolute URI for redirection

		if (apr_strnatcmp(ssl_session_id,"")){
			cookie_try = (char *)apr_psprintf(r->pool, "https://%s%s?__cookie_try=2", host, r->uri); // uri starts with a "/"
		} else {
			cookie_try = (char *)apr_psprintf(r->pool, "http://%s%s?__cookie_try=2", host, r->uri); // uri starts with a "/"
		}
		//cookie_try = (char *)apr_psprintf(r->pool, "%s?__cookie_try=2", r->uri);
		apr_table_setn(r->err_headers_out, "Location", cookie_try);
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED COOKIE_TRY=2");
                r->content_type = NULL;
                return HTTP_MOVED_TEMPORARILY;
            }

	// 2 COOKIE_TRY in URL
            if (rc1 == 9902){
                ap_log_rerror(PC_LOG_INFO, r, "mod_but: rc1 = 9902 aufgerufen");
		//TODO BUT: Use absolute URI for redirection

		if (apr_strnatcmp(ssl_session_id,"")){
			cookie_try = (char *)apr_psprintf(r->pool, "https://%s%s?__cookie_try=3", host, r->uri); // uri starts with a "/"
		} else {
			cookie_try = (char *)apr_psprintf(r->pool, "http://%s%s?__cookie_try=3", host, r->uri); // uri starts with a "/"
		}
		//cookie_try = (char *)apr_psprintf(r->pool, "%s?__cookie_try=3", r->uri);
		apr_table_setn(r->err_headers_out, "Location", cookie_try);
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED COOKIE_TRY=3");
                r->content_type = NULL;
                return HTTP_MOVED_TEMPORARILY;
            }

	// 3 COOKIE_TRY in URL
            if (rc1 == 9903){

                ap_log_rerror(PC_LOG_INFO, r, "mod_but: rc1 = 9903 aufgerufen");

		if (apr_strnatcmp(ssl_session_id,"")){
			no_cookie_support_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->client_refuses_cookies_url );
		} else {
			no_cookie_support_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->client_refuses_cookies_url );
		}

                apr_table_setn(r->err_headers_out, "Location", no_cookie_support_url);
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED NO_COOKIE_SUPPORT_URL");
                r->content_type = NULL;
                return HTTP_MOVED_TEMPORARILY;
            }

        // DECLINED
            if (rc1 == 9904){

                ap_log_rerror(PC_LOG_INFO, r, "mod_but: rc1 = 9904 aufgerufen");
                return DECLINED;
            }



        }else{
	/*
		If we are here, the client has sent a mod_but session (valid or invalid)

	*/



	    /*
	    	Check if Client Cookie is valid (and in SHM)

	    */



	    int shm_offset_number = validation_of_client_sent_session(r);
	    ap_log_rerror(PC_LOG_INFO, r, "mod_but: Offset Number is %d", shm_offset_number);

		if (shm_offset_number == -5540){
			/*
				In this case, the sent session has reached its time out
			*/
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Session timeout reached");
                        if (config->session_expired_url == NULL ){
                                ap_log_rerror(PC_LOG_INFO, r, "mod_but: MOD_BUT_SESSION_TIMEOUT_URL not configured in httpd.conf");
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
			if (apr_strnatcmp(ssl_session_id,"")){
				session_expired_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->session_expired_url );
			} else {
				session_expired_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->session_expired_url );
			}
			apr_table_setn(r->err_headers_out, "Location", session_expired_url);
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED SESSION_EXPIRED");
			r->content_type = NULL;
			return HTTP_MOVED_TEMPORARILY;
		}

		if (shm_offset_number == -5541){
			/*
				In this case, the sent session has reached its inactivity timeout
			*/
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Session inactivity timeout reached");
                        if (config->session_inactivity_timeout_url == NULL ){
                                ap_log_rerror(PC_LOG_INFO, r, "mod_but: MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL not configured in httpd.conf");
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
			if (apr_strnatcmp(ssl_session_id,"")){
				session_inactivity_timeout_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->session_inactivity_timeout_url );
			} else {
				session_inactivity_timeout_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->session_inactivity_timeout_url );
			}
			apr_table_setn(r->err_headers_out, "Location", session_inactivity_timeout_url);
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED SESSION_INACTIVITY_TIMEOUT_URL");
			r->content_type = NULL;
			return HTTP_MOVED_TEMPORARILY;
		}

                if (shm_offset_number == -5542){
                        /*
                                In this case, the sent session was in the history cache
                        */
                        ap_log_rerror(PC_LOG_INFO, r, "mod_but: Session found in history");

                        if (config->session_expired_url == NULL ){
                                ap_log_rerror(PC_LOG_INFO, r, "mod_but: MOD_BUT_SESSION_TIMEOUT_URL not configured in httpd.conf");
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
			if (apr_strnatcmp(ssl_session_id,"")){
				session_expired_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->session_expired_url );
			} else {
				session_expired_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->session_expired_url);
			}
                        apr_table_setn(r->err_headers_out, "Location", session_expired_url);
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED_SESSION_EXPIRED_URL");
                        r->content_type = NULL;
                        return HTTP_MOVED_TEMPORARILY;
                }

            	if (shm_offset_number == -5543){
                        /*
                                In this case, the sent session by the client is invalid, guessed, hacked or a shm error on our side
                        */
                        ap_log_rerror(PC_LOG_INFO, r, "mod_but: -5543 Invalid Session sent by the client");
                        ap_log_rerror(PC_LOG_INFO, r, "mod_but: config->session_hacking_attempt_url = [%s]", config->session_hacking_attempt_url);
			if (config->session_hacking_attempt_url == NULL ){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: MOD_BUT_SESSION_HACKING_ATTEMPT_URL not configured in httpd.conf");
				return HTTP_INTERNAL_SERVER_ERROR;
			}
			if (apr_strnatcmp(ssl_session_id,"")){
				session_hacking_attempt_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->session_hacking_attempt_url );
			} else {
				session_hacking_attempt_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->session_hacking_attempt_url);
			}
                        apr_table_setn(r->err_headers_out, "Location", session_hacking_attempt_url);
                        r->content_type = NULL;
                        return HTTP_MOVED_TEMPORARILY;
                }

            	if (shm_offset_number < 0){
                        /*
                                In this case, something went wrong with the return code
                        */
                        ap_log_rerror(PC_LOG_INFO, r, "mod_but: CRITICAL ERROR shm_offset_number < 0 ");
                        if (config->session_hacking_attempt_url == NULL ){
                                ap_log_rerror(PC_LOG_INFO, r, "mod_but: MOD_BUT_SESSION_HACKING_ATTEMPT_URL not configured in httpd.conf");
                                return HTTP_INTERNAL_SERVER_ERROR;
                        }
			if (apr_strnatcmp(ssl_session_id,"")){
				session_hacking_attempt_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->session_hacking_attempt_url );
			} else {
				session_hacking_attempt_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->session_hacking_attempt_url);
			}
                        apr_table_setn(r->err_headers_out, "Location", session_hacking_attempt_url);
                        r->content_type = NULL;
                        return HTTP_MOVED_TEMPORARILY;
                }



		/*
			If we are here, the client has sent a valid mod_but session

		*/
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: CLIENT SENT VALID MOD_BUT_SESSION");
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: CLIENT SENT VALID MOD_BUT SESSION");


		/*
			We will first check, if the requesting URI asks for the session destroy function
			This implements the "logout" functionality.

		*/

		rc2 = analyze_request_uri_for_session_destroy(r);

		if (rc2 == 8800){
			ap_log_rerror(PC_LOG_INFO, r, "mod_but.c: destroy pattern was not in URI = %s", r->uri);
			}
        if (rc2 == 8801){
			ap_log_rerror(PC_LOG_INFO, r, "mod_but.c: Problems with the following URI = %s", r->uri);
           }
		if (rc2 == 8802){
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: SESSION will be destroyed");
			delete_mod_but_session(shm_offset_number, r);

			if (apr_strnatcmp(ssl_session_id,"")){
				session_destroy_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->session_destroy_url);
			} else {
				session_destroy_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->session_destroy_url);
			}
			apr_table_setn(r->err_headers_out, "Location", session_destroy_url);
			r->content_type = NULL;
			return HTTP_MOVED_TEMPORARILY;
		}


		/*
			If we are here, the requesting URI does not want to be destroyed and we analyze
			the request for the cookie_tests. If we are still in the cookie test phase, we have to give the client
			the Original URI (from the first request) as redirect
		*/
		pshm_offset_number = apr_itoa(r->pool, shm_offset_number);
		if (pshm_offset_number == NULL ){
               		ap_log_rerror(PC_LOG_INFO, r, "mod_but: pshm_offset_number is null!!!");
                        return HTTP_INTERNAL_SERVER_ERROR;
		}
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: WRITE APR: r->notes SHMOFFSET [%s]", pshm_offset_number);
		apr_table_set(r->notes, "SHMOFFSET", pshm_offset_number);



		ap_log_rerror(PC_LOG_INFO, r, "mod_but: VOR analyze_request_arguments_for_cookie_test");
		rc1 = analyze_request_arguments_for_cookie_test(r);
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: RETURN VALUE OF COOKIE_TEST ROUTINE WHEN SESSION IS VALID %d", rc1);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: NACH analyze_request_arguments_for_cookie_test");
	    	cs_rmm = find_cs_rmm();
		off = find_cs_rmm_off();
		c = apr_rmm_addr_get(cs_rmm, off[shm_offset_number]);


		// cookie is sent by the client, it is a valid session and the requesting URL contains a COOKIE TRY parameter
		if ((rc1 == 9901)||(rc1 == 9902)||(rc1 == 9903)){
            if (c->session_firsturl == NULL ){
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: c->session_firsturl is empty");
                	return HTTP_INTERNAL_SERVER_ERROR;
            } 

    ap_log_rerror(PC_LOG_CRIT, r, "mod_but: CLIENT SESSION IS VALID AND COOKIE_TRY IN URL"); 
    re4 = pcre_compile("\r\n", 0, &error4, &error_offset4, NULL);

    if (re4 == NULL) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: return code of pcre_compile is NULL");
    }

    rc4 = pcre_exec(re4, NULL, r->uri, strlen(r->uri), 0, 0, re_vector4, 3072);
    ap_log_rerror(PC_LOG_CRIT, r, "mod_but: Rc4 contains %d",rc4); 

    if (rc4 < 0) {
        ap_log_rerror(PC_LOG_CRIT, r, "mod_but: r->uri does not contain CR/LF [%s]", r->uri);

        if (apr_strnatcmp(ssl_session_id,"")){
                session_firsturl = (char *)apr_psprintf(r->pool, "https://%s%s", host, c->session_firsturl);
        } else {
                session_firsturl = (char *)apr_psprintf(r->pool, "http://%s%s", host, c->session_firsturl);
        }
        apr_table_setn(r->err_headers_out, "Location", session_firsturl);
        ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED_SESSION_FIRSTURL");
        r->content_type = NULL;
	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: AAAAAAAAAAAAAAAA FURSTURL %s", session_firsturl);
        return HTTP_MOVED_TEMPORARILY;

    }

    if (rc4 < 0 && rc4 != PCRE_ERROR_NOMATCH) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: r->uri does not contain CR/LF [%s]", r->uri);

	if (apr_strnatcmp(ssl_session_id,"")){
		session_firsturl = (char *)apr_psprintf(r->pool, "https://%s%s", host, c->session_firsturl);
	} else {
		session_firsturl = (char *)apr_psprintf(r->pool, "http://%s%s", host, c->session_firsturl);
	}
	apr_table_setn(r->err_headers_out, "Location", session_firsturl);
	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED_SESSION_FIRSTURL");
	r->content_type = NULL;
	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: AAAAAAAAAAAAAAAA FURSTURL %s", session_firsturl);
	return HTTP_MOVED_TEMPORARILY;
    }

    if (rc4 == 0) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: PCRE output vector too small (%d)", 3072/3-1);
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with pcre CRLF = %s", r->uri);
	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: BBBBBBBBBBBBBBBBBB");
	return DECLINED;
    }

	if (rc4 > 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: ATTACK!!!! r->uri contains CR/LF [%s]", r->uri);
		apr_cpystrn(c->session_firsturl, "ATTACK", sizeof(c->session_firsturl));
		apr_table_setn(r->err_headers_out, "Location", session_firsturl);
		r->content_type = NULL;
		ap_log_rerror(PC_LOG_CRIT, r, "mod_but: CCCCCCCCCCCCCCCCC");
		return HTTP_MOVED_TEMPORARILY;

	}
	}

	ap_log_rerror(PC_LOG_CRIT, r, "mod_but: IF WE ARE HERE, THE REQUEST WILL BE AUTHORIZED (NO COOKIE TRY IN URL)");


		/*
			Now let's do the authorization stuff, if enabled by config

		*/

		if (config->authorization_enabled) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Authorization checks are enabled");
			rc3 = do_authorization(shm_offset_number, r);
			/*
				if return code 
				7700: 	client not logged in yet
				7701:	client is properly authenticated
				7702:	authentication is not required for this url	
				7703:	client is properly authenticated, but not authorized
				7704: 	client is properly authenticated, but with too low auth_strength (1)
				7705:   client is properly authenticated, but with too low auth_strength (2)
				7706: 	DECLINED
			*/
			if (rc3 == 7700)
			{
				/*
					If we are here, the requesting URI requires authentication and the client is not logged in yet.
				*/
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: URI requres auth, but user not logged in yet");
				


				ap_log_rerror(PC_LOG_INFO, r, "mod_but: Client is not logged in");
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: orig_url [%s]", c->orig_url_before_logon);
				apr_cpystrn(c->orig_url_before_logon, r->uri, sizeof(c->orig_url_before_logon));
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: CORE SET ORIG_URL TO %s", c->orig_url_before_logon);
				c->logon_flag=1;
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: Set logon_flag to[%d]", c->logon_flag);

				if (dconfig->logon_server_url){

					/*
						If we are here, a Login SERVER is configured for this Location

					*/


					ap_log_rerror(PC_LOG_INFO, r, "mod_but: Our Dir Config is [%s]", dconfig->logon_server_url);
                        		if (dconfig->logon_server_url == NULL ){
                                		ap_log_rerror(PC_LOG_INFO, r, "mod_but: dconfig->logon_server_url is empty");
                                		return HTTP_INTERNAL_SERVER_ERROR;
                        		}
					if (apr_strnatcmp(ssl_session_id,"")){
						logon_server_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, dconfig->logon_server_url);
					} else {
						logon_server_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, dconfig->logon_server_url);
					}
					apr_table_setn(r->err_headers_out, "Location", logon_server_url);
					ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED LOGON_SERVER_URL");
					r->content_type = NULL;
					return HTTP_MOVED_TEMPORARILY;
				}else{

					/*
						If we are here, no LOGIN SERVER is configured for this Location
					*/
					ap_log_rerror(PC_LOG_INFO, r, "mod_but: NULL Our Dir Config is [%s]", dconfig->logon_server_url);
                                        if (config->global_logon_server_url == NULL ){
                                                ap_log_rerror(PC_LOG_INFO, r, "mod_but: config->global_logon_server_url is empty");
                                                return HTTP_INTERNAL_SERVER_ERROR;
                                        }

					if (apr_strnatcmp(ssl_session_id,"")){
						global_logon_server_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->global_logon_server_url);
					} else {
						global_logon_server_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->global_logon_server_url);
					}
					apr_table_setn(r->err_headers_out, "Location", global_logon_server_url);
					ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED GLOBAL_LOGON_SERVER_URL");
					r->content_type = NULL;
					return HTTP_MOVED_TEMPORARILY;
				}

			}

			if (rc3 == 7701)
			{
					ap_log_rerror(PC_LOG_INFO, r, "mod_but: client is properly authenticated");
			}

			if (rc3 == 7702)
			{
					ap_log_rerror(PC_LOG_INFO, r, "mod_but: authentication is not required for this url");
			}

			if (rc3 == 7703)
			{
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: Client ist properly authenticated, but not allowed to request the url");
				if (apr_strnatcmp(ssl_session_id,"")){
					service_list_error_url = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->service_list_error_url);
				} else {
					service_list_error_url = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->service_list_error_url);
				}
				apr_table_setn(r->err_headers_out, "Location", service_list_error_url);
				ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED SERVICE_LIST_ERROR_URL");
				r->content_type = NULL;
				return HTTP_MOVED_TEMPORARILY;
				
			}

			if (rc3 == 7704)
			{
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: Client authenticated, but auth_strength is too low");
				if (config->global_logon_server_url_1 == NULL ){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but: config->global_logon_server_url_1 is empty");
					return HTTP_INTERNAL_SERVER_ERROR;
                                }

				if (apr_strnatcmp(ssl_session_id,"")){
					global_logon_server_url_1 = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->global_logon_server_url_1);
				} else {
					global_logon_server_url_1 = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->global_logon_server_url_1);
				}
				apr_table_setn(r->err_headers_out, "Location", global_logon_server_url_1);
				ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED GLOBAL_LOGON_SERVER_URL 1");
				r->content_type = NULL;
				return HTTP_MOVED_TEMPORARILY;
				
			}

			if (rc3 == 7705)
			{
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: Client authenticated, but auth_strength is too low");
				if (config->global_logon_server_url_2 == NULL ){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but: config->global_logon_server_url_2 is empty");
					r->content_type = NULL;
					return HTTP_INTERNAL_SERVER_ERROR;
                                }

				if (apr_strnatcmp(ssl_session_id,"")){
					global_logon_server_url_2 = (char *)apr_psprintf(r->pool, "https://%s%s", host, config->global_logon_server_url_2);
				} else {
					global_logon_server_url_2 = (char *)apr_psprintf(r->pool, "http://%s%s", host, config->global_logon_server_url_2);
				}
				apr_table_setn(r->err_headers_out, "Location", global_logon_server_url_2);
				ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED GLOBAL_LOGON_SERVER_URL 2");
				r->content_type = NULL;
				return HTTP_MOVED_TEMPORARILY;
				
			}

				if (rc3 == 7706)
				{
					ap_log_rerror(PC_LOG_INFO, r, "mod_but: service_list PCRE output vector too small");
					return DECLINED;
				}

		}else{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: Authorization checks are disabled or LOGON is not required");
		}

		/*
			If we are here, the client is properly authenticated and we start proceeding
			the request. 
		*/



		/*
			This is the callback function, if the user was previously successfully authenticated
			and the c->logon_flag = 1. The flag was set to 1 couple of lines above, if uri requires authentication but is not authenticated yet.

			we need to redirect the client to the OrigURL (initial uri, before authentication)
		*/
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: LOGON_FLAG [%d]", c->logon_flag);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: LOGON_STATE [%d]", c->logon_state);
		if (c->logon_flag == 1 && c->logon_state == 1){
			if (c->orig_url_before_logon != NULL){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: SEND REDIRECT AFTER SUCCESSFUL LOGON");
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: REDIRECT TO OrigURL: [%s]", c->orig_url_before_logon);

				if (apr_strnatcmp(ssl_session_id,"")){
					orig_url_before_logon = (char *)apr_psprintf(r->pool, "https://%s%s", host, c->orig_url_before_logon);
				} else {
					orig_url_before_logon = (char *)apr_psprintf(r->pool, "http://%s%s", host, c->orig_url_before_logon);
				}
				apr_table_setn(r->err_headers_out, "Location", orig_url_before_logon);
				ap_log_rerror(PC_LOG_CRIT, r, "mod_but: FINISHED ORIG_URL BEFORE LOGON");
				r->content_type = NULL;
				c->logon_flag=0;
				return HTTP_MOVED_TEMPORARILY;
			}else{
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: PROBLEM: ORIG_URL is empty");
			}
		}else{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but: LOGON_FLAG or LOGON_STATE 0");
		}

		/*
			If the cookiestore has some "values", we will include them into the request header
			ADD Headers into the backend request
		*/
	    	if (c->link_to_cookiestore != -1){
			add_headers_into_request_from_cookiestore(r, c->link_to_cookiestore);

			// now all cookies from the cookiestore are within the r->notes REQUEST_COOKIES
			if (apr_table_get(r->notes, "REQUEST_COOKIES") != NULL) {
				apr_table_set(r->headers_in, "Cookie", apr_table_get(r->notes, "REQUEST_COOKIES"));
			}
			
		}


		/*
			Ok  now we will proceed with the request
		*/
		ap_log_rerror(PC_LOG_INFO, r, "mod_but: ========= STOP =========== mod_but hook is executed by apache core");
	    	return OK;
        }
	return OK;
}


/*
	Performs per directory configuration during httpd startup phase
*/
static void *mod_but_create_dir_conf(apr_pool_t *p, char *dummy)
{
  mod_but_dir_t *conf;

   conf = (mod_but_dir_t *)apr_pcalloc(p, sizeof(mod_but_dir_t));

  if(conf)
  {
    conf->logon_server_url = NULL;
  }

  return conf;
}


/*
	Performs per server configuration during httpd startup phase
*/
static void *mod_but_create_server_conf(apr_pool_t *p, server_rec *s)
{
    mod_but_server_t *conf;

    conf = (mod_but_server_t *)apr_pcalloc(p, sizeof(mod_but_server_t));
    conf->client_refuses_cookies_url = NULL;
    conf->cookie_name = NULL;
    conf->cookie_domain = NULL;
    conf->cookie_path = NULL;
    conf->cookie_expiration = NULL;
    conf->session_free_url = NULL;

    return conf;
}


/*
	The implementation of the configuration directive functions is in mod_but_config.c
*/
static const command_rec mod_but_cmds[] =
{
	AP_INIT_FLAG("MOD_BUT_ENABLED", mod_but_enabled_on, NULL, RSRC_CONF, "mod_but is enabled"),
	AP_INIT_TAKE1("MOD_BUT_CLIENT_REFUSES_COOKIES_URL", mod_but_client_refuses_cookies, NULL, RSRC_CONF, "Configure mod_but Redirect 3"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_NAME", mod_but_set_cookie_name, NULL, RSRC_CONF, "Configure mod_but Cookie Name"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_DOMAIN", mod_but_set_cookie_domain, NULL, RSRC_CONF, "Configure mod_but Cookie Domain"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_PATH", mod_but_set_cookie_path, NULL, RSRC_CONF, "Configure mod_but Cookie Path"),
	AP_INIT_TAKE1("MOD_BUT_COOKIE_EXPIRATION", mod_but_set_cookie_expiration, NULL, RSRC_CONF, "Configure mod_but Cookie Expiration Time"),
	AP_INIT_FLAG("MOD_BUT_COOKIE_SECURE", mod_but_set_cookie_secure, NULL, RSRC_CONF, "Configure mod_but Cookie Secure Flag"),
	AP_INIT_FLAG("MOD_BUT_COOKIE_HTTPONLY", mod_but_set_cookie_httponly, NULL, RSRC_CONF, "Configure mod_but HTTPOnly Flag"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_FREE_URL", mod_but_set_session_free_url, NULL, RSRC_CONF, "Configure mod_but free URL's"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_TIMEOUT", mod_but_set_session_timeout, NULL, RSRC_CONF, "Configure session timeout"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_HACKING_ATTEMPT_URL", mod_but_set_session_hacking_attempt_url, NULL, RSRC_CONF, "Configure session timeout URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_INACTIVITY_TIMEOUT", mod_but_set_session_inactivity_timeout, NULL, RSRC_CONF, "Configure session inactivity timeout"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL", mod_but_set_session_inactivity_timeout_url, NULL, RSRC_CONF, "Configure session inactivity timeout URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_TIMEOUT_URL", mod_but_set_session_expired_url, NULL, RSRC_CONF, "Configure session expired URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_RENEW_URL", mod_but_set_session_renew_url, NULL, RSRC_CONF, "Configure session renew URL"),
	AP_INIT_TAKE1("MOD_BUT_ALL_SHM_SPACE_USED_URL", mod_but_set_all_shm_used_url, NULL, RSRC_CONF, "Configure No more SHM URL"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_TIMEOUT_HISTORY", mod_but_set_session_timeout_history, NULL, RSRC_CONF, "Configure session timeout history"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_DESTROY", mod_but_set_session_destroy, NULL, RSRC_CONF, "Configure session destroy URI"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_DESTROY_URL", mod_but_set_session_destroy_url, NULL, RSRC_CONF, "Configure session destroy URL"),
	AP_INIT_FLAG("MOD_BUT_AUTHORIZATION_ENABLED", mod_but_authorization_enabled_on, NULL, RSRC_CONF, "Authorization is enabled"),
	AP_INIT_TAKE1("MOD_BUT_LOGON_SERVER_URL", ap_set_string_slot, (void*)APR_OFFSETOF(mod_but_dir_t, logon_server_url), OR_ALL, "Per Dir Config"),
	AP_INIT_TAKE1("MOD_BUT_LOGON_REQUIRED", ap_set_string_slot, (void*)APR_OFFSETOF(mod_but_dir_t, logon_required), OR_ALL, "Per Dir Config"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_SERVER_URL", mod_but_global_logon_server_url, NULL, RSRC_CONF, "Configure Global Logon Server URL"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_SERVER_URL_1", mod_but_global_logon_server_url_1, NULL, RSRC_CONF, "Configure Global Logon Server URL 1"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_SERVER_URL_2", mod_but_global_logon_server_url_2, NULL, RSRC_CONF, "Configure Global Logon Server URL 2"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_AUTH_COOKIE_NAME", mod_but_global_logon_auth_cookie_name, NULL, RSRC_CONF, "Configure Global Logon Cookie Name"),
	AP_INIT_TAKE1("MOD_BUT_GLOBAL_LOGON_AUTH_COOKIE_VALUE", mod_but_global_logon_auth_cookie_value, NULL, RSRC_CONF, "Configure Global Logon Cookie Value"),
	AP_INIT_TAKE1("MOD_BUT_SESSION_STORE_FREE_COOKIES", mod_but_set_session_store_free_cookies, NULL, RSRC_CONF, "Configure Cookies, which are not handled by the session store"),
	AP_INIT_TAKE1("MOD_BUT_SERVICE_LIST_COOKIE_NAME", mod_but_set_service_list_cookie_name, NULL, RSRC_CONF, "Configure Service List Cookie Name"),
	AP_INIT_TAKE1("MOD_BUT_SERVICE_LIST_COOKIE_VALUE", mod_but_set_service_list_cookie_value, NULL, RSRC_CONF, "Configure Cookies, which are not handled by the session store"),
	AP_INIT_TAKE1("MOD_BUT_SERVICE_LIST_AUTH_ERROR_URL", mod_but_set_service_list_error_url, NULL, RSRC_CONF, "Configure error page, if the user is not authorized for a specific request"),
	AP_INIT_FLAG("MOD_BUT_SERVICE_LIST_ENABLED", mod_but_service_list_enabled_on, NULL, RSRC_CONF, "mod_but service list enabled"),
	AP_INIT_TAKE1("MOD_BUT_AUTHORIZED_LOGON_URL", mod_but_set_authorized_logon_url, NULL, RSRC_CONF, "Configure regexp url, from where you accept logon cookies"),
	AP_INIT_TAKE1("MOD_BUT_LOCATION_ID", ap_set_int_slot, (void*)APR_OFFSETOF(mod_but_dir_t, mod_but_location_id), OR_ALL, "LOCATION_ID Per Dir Config"),
	AP_INIT_TAKE1("MOD_BUT_AUTH_STRENGTH", ap_set_int_slot, (void*)APR_OFFSETOF(mod_but_dir_t, mod_but_auth_strength), OR_ALL, "AUTH STRENGTH Per Dir Config"),
    	{NULL}
};


/*
	Definition of MOD_BUT hooks. This is parsed by httpd during startup
	and the symbols are loaded into the httpd core. 
*/
static void mod_but_register_hooks (apr_pool_t *p)
{
	static const char * const cfgPost[]={ "http_core.c", NULL };
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
	Declare config files
*/
module AP_MODULE_DECLARE_DATA but_module =
{
	STANDARD20_MODULE_STUFF, 		// standard stuff; no need to mess with this.
	mod_but_create_dir_conf,			// create per-directory configuration structures - we do not.
	NULL, 						// merge per-directory - no need to merge if we are not creating anything.
	mod_but_create_server_conf, 		// create per-server configuration structures.
	NULL, 						// merge per-server - hrm - examples I have been reading don't bother with this for trivial cases.
	mod_but_cmds,					// configuration directive handlers
	mod_but_register_hooks, 			// request handlers
};

