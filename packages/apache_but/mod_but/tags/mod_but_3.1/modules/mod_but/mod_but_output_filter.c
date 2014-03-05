/*#############################################
#
# Title:        mod_but_output_filter.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/


#include "mod_but.h"

int mod_but_analyze_response_headers(void *result, const char *key, const char *value)
{

	/*
		This function is called for all HTTP RESPONSE HEADER

		HTTP/1.1 302 Found
		Date: Mon, 22 Aug 2005 21:10:45 GMT
		Set-Cookie: E2=jLllj33EsXhInvgW5KDkMtzB4YcqLy2Eawv1EAbY0K3NGUHczLF1oIrJ7bURyw1; domain=but.ch;  path=/;
		Set-Cookie: TEST=ABC;
		Set-Cookie: FREECOOKIE=123;
		Location: /cgi/cgi-bin/printenv?__cookie_try=1
		Content-Length: 281
		Content-Type: text/html; charset=iso-8859-1

		It checks the Set-Cookie headers.


	*/
	cookie_res * cr = (cookie_res *) result;
	request_rec *r = cr->r;
	apr_rmm_t *cs_rmm = find_cs_rmm();
	apr_rmm_off_t *off = find_cs_rmm_off();
	mod_but_server_t *config;
	mod_but_dir_t *dconfig = ap_get_module_config(r->per_dir_config, &but_module);

	pcre *re;  					// the regular expression
	const char *error;				// error text for the failed regex compilation
	int error_offset;				// offset of the regex compilation error, if any
	int rc = 0;					// return code of pcre_exec
	int re_vector[3072];

	apr_int64_t num_set_cookie;

	apr_int64_t auth_strength;

	char *qa = (char *)apr_pstrdup(r->pool, value);
	char *p, *last;


	ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: CALLING OUTPUT FILTER");

	config = ap_get_module_config(r->server->module_config, &but_module);
	if (config == NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Illegal server record (output filter)");
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: END OF OUTPUT FILTER");
       		return DECLINED;
	}

	ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Request URI [%s]", r->uri);
	ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Working with SHM offset [%s]", apr_table_get(r->notes, "SHMOFFSET"));


	re = pcre_compile("cOOkIe", PCRE_CASELESS, &error, &error_offset, NULL);

	if (re == NULL) {
        	ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: return code of pcre_compile in Cookie Store is NULL");
		return DECLINED;
	}

	if(key==NULL){
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: key is NULL");
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: END OF OUTPUT FILTER");
		return DECLINED;
	}

	rc = pcre_exec(re, NULL, key, strlen(key), 0, 0, re_vector, 3072);


	if (rc < 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Set-Cookie was not in ARGS = %s", key);
		return DECLINED;
	}


	if (rc == 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: PCRE output vector too small (%d)", 3072/3-1);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Problems with the following ARGS = %s", key);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: END OF OUTPUT FILTER");
		return DECLINED;
	}

	if (rc > 0) {
		char* val1;
		char* substr;
		char* key1;
		mod_but_cookie_cookiestore *csp;
		apr_rmm_t *cs_rmm_cookiestore;
		apr_rmm_off_t *off_cookiestore;

		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: ====================== FIND SET-COOKIE HEADER =====================");
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Found Set-Cookie [%s]=[%s]", key,value);


		/*
			Store Set-Cookie attributes into mod_but_cookie_cookiestore struct

		*/
		substr = strchr(value, '=' );
		key1 = (char*)apr_pstrndup(r->pool, value, (strlen(value)-strlen(substr)) );
		substr++;	// now substr points to the value
		if (strchr(substr,';')) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: OUTPUT_FILTER: COOKIE HAS \";\"");
			val1 = (char*)apr_pstrndup( r->pool, substr, (strlen(substr)-strlen(strchr(substr,';'))) );
		} else {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: OUTPUT_FILTER: COOKIE HAS NO \";\"");
			val1 = (char*)apr_pstrndup( r->pool, substr, (strlen(substr)));
		}

		if (!apr_strnatcmp(key1, "") && !apr_strnatcmp(val1, "")){
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Unparsed %s - %s", key1, val1);
			return OK;
		}

		csp = apr_palloc(r->pool, sizeof(mod_but_cookie_cookiestore));
		apr_cpystrn(csp->cookie_name, key1, sizeof(csp->cookie_name));
		apr_cpystrn(csp->cookie_value, val1, sizeof(csp->cookie_value));

		if (dconfig == NULL) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: Illegal Directory Config (location_id)");
		}
		csp->location_id = dconfig->mod_but_location_id;	// remember the location, for which a cookie was set. 
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: COOKIE LOCATION ID [%d]", csp->location_id);


		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: PARSED COOKIENAME AND VALUE [%s]-[%s]", csp->cookie_name, csp->cookie_value);


		cs_rmm_cookiestore = find_cs_rmm_cookiestore();
		off_cookiestore = find_cs_rmm_off_cookiestore();

		if(apr_table_get(r->notes, "SHMOFFSET")){
			apr_int64_t i = apr_atoi64(apr_table_get(r->notes, "SHMOFFSET"));
			mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[i]);

			/*
				1) LOGON cookie?
				2) SERVICE_LIST cookie?
				3) FREE COOKIE?
				4) MOD_BUT_SESSION?
				5) Others
			*/

			/*
				1) Lets see, if the cookie is a LOGON cookie
			*/
			
			if (!apr_strnatcmp(csp->cookie_name, config->global_logon_auth_cookie_name)){
				/*
					First, we set the logon flag to true
				*/
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: FOUND LOGON Header");
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Requesting r->uri is: %s", r->uri);

				re = pcre_compile(config->authorized_logon_url, PCRE_CASELESS, &error, &error_offset, NULL);
				rc = pcre_exec(re, NULL, r->uri, strlen(r->uri), 0, 0, re_vector, 3072);


				if (rc < 0) {
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: LOGON=ok from unauthorized source - we denied it");
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Unsetting LOGON=ok from response header");
					return DECLINED;
				}


				if (rc == 0) {
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: PCRE output vector too small (%d)", 3072/3-1);
					return DECLINED;
				}

				if (rc > 0) {					
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: LOGON comes form a trusted/authorized source");

					if (!apr_strnatcmp(csp->cookie_value, config->global_logon_auth_cookie_value)){
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: LOGON=ok comes form a trusted/authorized source");
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: LOGON=ok (set c->logon_state=1)");
						c->logon_state=1;
						apr_table_set(r->notes, "LOGON_STATUS", "OK");
					}

					// unset LOGON cookie from the response header
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Unsetting LOGON=ok from response header");
					return DECLINED;
				}




			}




			/*
				3) Check if we have a FREE Cookie (configured in httpd.conf)
				We do not store FREE Cookies into the cookie store

			*/

			if(config->session_store_free_cookies){
				char *temp;

				ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: MOD_BUT_SESSION_STORE_FREE_COOKIES is configured");

				re = pcre_compile(config->session_store_free_cookies, 0, &error, &error_offset, NULL);

				if (re == NULL) {
				// ap_log_rerror(PC_LOG_INFO,			
				}

				temp = apr_pstrcat(r->pool, key1, "=", value, NULL);
				rc = pcre_exec(re, NULL, temp, strlen(temp), 0, 0, re_vector, 3072);


				if (rc < 0) {
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Set-Cookie is not a FREE COOKIE key = %s | value = %s", key1, value);
				}


				if (rc == 0) {
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: PCRE output vector too small (%d)", 3072/3-1);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Problems with the following ARGS = %s", key1);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: END OF OUTPUT FILTER");
					return DECLINED;
				}

				if (rc > 0) {
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: FOUND FREE COOKIE [%s] [%s]", key1, value);
					num_set_cookie = apr_atoi64(apr_table_get(r->notes, "NUM_SET_COOKIE"));
					num_set_cookie += 1;
					apr_table_set(r->notes, "NUM_SET_COOKIE", apr_itoa(r->pool, num_set_cookie));
					apr_table_set(r->notes, apr_itoa(r->pool, num_set_cookie), value);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter: VALUE IS [%s]", apr_table_get(r->notes, apr_itoa(r->pool, num_set_cookie)));
					return DECLINED;
				}

			}

			/*
				4) If the Cookie is the MOD_BUT_SESSION, we don't want to have that cookie stored in the cookie store
				This means, that NO backend application is allowed to have the same cookie name as the MOD_BUT_SESSION
			*/
			if (!apr_strnatcmp(key1, config->cookie_name)){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Set-Cookie is MOD_BUT_SESSION");
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: END OF OUTPUT FILTER");
				return DECLINED;
			}

			/*

				5) If LOGON=ok, we will store the special meaning cookies in a special way here. 				

			*/
			if (apr_table_get(r->notes, "LOGON_STATUS") != NULL){
				if (!apr_strnatcmp(key1, "MOD_BUT_AUTH_STRENGTH")){
					
					auth_strength = apr_atoi64(val1);
					
					if ((auth_strength >= 0) || (auth_strength <= 2)) {
						c->auth_strength=auth_strength;
					} else {
						c->auth_strength= 0; // default value, if auth_strength is not parseable or greater than 2
					}
					return DECLINED;
				}


				/*
					Lets see, if the SERVICE_LIST cookie is set
				*/
				if (!apr_strnatcmp(csp->cookie_name, config->service_list_cookie_name)){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: FOUND SERVICE LIST Cookiename (Authorization Regex)");
					apr_cpystrn(c->service_list, val1, sizeof(c->service_list));
					return DECLINED;
				}
				
				if (!apr_strnatcmp(key1, "MOD_BUT_BACKEND_SESSION")){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: FOUND MOD_BUT_BACKEND_SESSION [%s]", value);
					char *p1 = NULL; 
					char *p2 = NULL;
					char *p3 = NULL;
					char *p11 = NULL;
					char *p21 = NULL;
					char *p31 = NULL;
					for(p = (char *)apr_strtok(qa, "; ", &last); p != NULL; p = (char *)apr_strtok(NULL, "; ", &last))
					{
						p1 = strstr(p, "bname");
						if(p1){
							ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: bname found [%s]", p1);
							p1 += strlen("bname");
							if(*p1 == '=')
							{
								ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: bname [%s]", (char *)apr_pstrdup(r->pool, p1+1));
								p11 = apr_pstrdup(r->pool, p1+1);
							}
						}
						p2 = strstr(p, "bvalue");
						if(p2){
							ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: bvalue [%s]", p2);
							p2 += strlen("bvalue");
							if(*p2 == '=')
							{
								ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: bvalue [%s]", (char *)apr_pstrdup(r->pool, p2+1));
								p21 = apr_pstrdup(r->pool, p2+1);
							}
						}
						p3 = strstr(p, "bclearance");
						if(p3){
							ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: bclearance [%s]", p3);
							p3 += strlen("bclearance");
							if(*p3 == '=')
							{
								ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: bclearance [%s]", (char *)apr_pstrdup(r->pool, p3+1));
								p31 = apr_pstrdup(r->pool, p3+1);
							}
						}
					}
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: bname found [%s]=[%s] CLEAR [%s]", p11,p21,p31);

					for(p31 = apr_strtok(p31, ",", &last); p31 != NULL; p31 = apr_strtok(NULL, ",", &last))
					{
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: P31 = [%s]", p31);

						apr_cpystrn(csp->cookie_name, p11, sizeof(csp->cookie_name));
						apr_cpystrn(csp->cookie_value, p21, sizeof(csp->cookie_value));
						csp->location_id = apr_atoi64(p31);


						if (c->link_to_cookiestore == -1){
							/*
								Here we have to update the c->link_to_cookiestore
			
							*/
							int cookiestore_offset = find_empty_cookiestore_slot(r);
							if (cookiestore_offset >= 0){
								mod_but_cookie_cookiestore *cs;
			
								/*
									If we are here, we found an empty cookiestore shm storage we can put our stuff into
			
								*/
								
								cs = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[cookiestore_offset]);
								apr_cpystrn(cs->cookie_name, p11, sizeof(cs->cookie_name));
								apr_cpystrn(cs->cookie_value, p21, sizeof(cs->cookie_value));
								c->link_to_cookiestore = cookiestore_offset;
								cs->location_id = apr_atoi64(p31);
							}else{
								/*
									If we are here, we did not have more cookiestore shm
								*/
								ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Unable finding new cookiestore slot");
								apr_table_set(r->notes, "CS_SHM" , "PROBLEM");
							}
						} else {
							int status;
							// if we are here, we are not the first cookie to be saved. 
							status = store_cookie_in_cookiestore(r, c->link_to_cookiestore, csp);
							if (status == 30){
								ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: All Cookiestore SHM used [%d] - Status", status);
								apr_table_set(r->notes, "CS_SHM" , "PROBLEM");
							}
						}

						
					}

					/*
						Loop around clearance and save the cookies into the correct location_id
					*/


					return DECLINED;
				}
			}

			/*
				6) If the Cookie does not have a special meaning to us, let's store them in the session store (without DLS)
			*/

						
			// store all other cookies to the cookiestore
			if (c->link_to_cookiestore == -1){
				/*
					Here we have to update the c->link_to_cookiestore

				*/
				int cookiestore_offset = find_empty_cookiestore_slot(r);
				if (cookiestore_offset >= 0){
					mod_but_cookie_cookiestore *cs;

					/*
						If we are here, we found an empty cookiestore shm storage we can put our stuff into

					*/
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: OUTPUT FILTER: ANCHOR LINK TO COOKIE STORE [%d]", cookiestore_offset);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Copy HEADER @ CS offset %d", cookiestore_offset);
					cs = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[cookiestore_offset]);
					apr_cpystrn(cs->cookie_name, key1, sizeof(cs->cookie_name));
					apr_cpystrn(cs->cookie_value, val1, sizeof(cs->cookie_value));

					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: STOREING NEW cookie_name [%s]=[%s] in CookieStore", cs->cookie_name, cs->cookie_value);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: STOREING NEW cookie_name [%s] and cookie_value [%s] @ CS offset [%d] and cookie_next is [%d]", cs->cookie_name, cs->cookie_value, cookiestore_offset, cs->cookie_next);

					c->link_to_cookiestore = cookiestore_offset;
					cs->location_id = dconfig->mod_but_location_id;

					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: STOREING NEW cookie_name [%s] = [%s] ", cs->cookie_name, cs->cookie_value);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: STOREING NEW cookie_name [%s] and cookie_value [%s] @ CS offset [%d] and cookie_next is [%d] and cookie_before is [%d]", cs->cookie_name, cs->cookie_value, cookiestore_offset, cs->cookie_next, cs->cookie_before);
				}else{
					/*
						If we are here, we did not have more cookiestore shm
					*/
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: Unable finding new cookiestore slot");
					apr_table_set(r->notes, "CS_SHM" , "PROBLEM");
				}
			} else {
				int status;
				// if we are here, we are not the first cookie to be saved. 
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: STORE [%s]=[%s]", csp->cookie_name,csp->cookie_value);
				status = store_cookie_in_cookiestore(r, c->link_to_cookiestore, csp);
				if (status == 30){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: All Cookiestore SHM used [%d] - Status", status);
					apr_table_set(r->notes, "CS_SHM" , "PROBLEM");
				}
			}
		}
	}
	ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: END OF OUTPUT FILTER");
	return DECLINED;
}

