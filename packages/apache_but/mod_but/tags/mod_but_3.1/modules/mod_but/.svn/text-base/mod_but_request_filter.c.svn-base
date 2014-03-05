/*#############################################
#
# Title:        mod_but_request_filter.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/


#include "mod_but.h"

int filter_request_headers(request_rec *r, const char *value){

	/*
		Filters all request headers from the Internet request.  

			leave MOD_BUT_SESSION in request
			leave SESSION_STORE_FREE_COOKIES in request
			unset all other cookies the client is sending
							const char *insert_cookie = NULL;
							const char *new_cookie = NULL;
							const char *existing_cookie = NULL; 


	*/

	const char *insert_cookie = NULL;
	const char *new_cookie = NULL;
	const char *existing_cookie = NULL; 

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
	ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: FILTER REQUEST HEADER [%s]", value);


	/*
		First, we unset all headers here

	*/
	apr_table_unset(r->headers_in, "Cookie");
	ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: Unsetting all request headers");


	if(value){
		pcre *re;  					// the regular expression
		const char *error;				// error text for the failed regex compilation
		int error_offset;				// offset of the regex compilation error, if any
		int rc = 0;					// return code of pcre_exec
		int re_vector[3072];

		char *qa = (char *)apr_pstrdup(r->pool, value);
		char *p, *last;

		/*
			Loop through all a=b; c=d; e=f values
			Cookies are sent in a single line from the browser Cookie: jsessionid=1234; foo=3322;

		*/
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: REQUEST FILTER: COOKIES BEFORE PARSING: [%s]", value);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: config->cookie_name [%s]", config->cookie_name);

		for(p = (char *)apr_strtok(qa, "; ", &last); p != NULL; p = (char *)apr_strtok(NULL, "; ", &last))
		{



			/*
				Make sure we insert the MOD_BUT_SESSION into headers_in, after we unset all
			*/
			char *p1 = strstr(p, config->cookie_name);
			if(p1){
				/*
					If we are here, we are analyzing the MOD_BUT_SESSION Cookie
				*/
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: MOD_BUT_SESSION FOUND [%s]", p1);

				p1 += strlen(config->cookie_name);

				if(*p1 == '=')
				{
					char *mod_but_session = (char *)apr_pstrdup(r->pool, p1+1);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: MOD_BUT_SESSION (NOTES) [%s]", mod_but_session);
					apr_table_set(r->notes, config->cookie_name , mod_but_session);
				}
			}else{

				/*
					Now let's see the other cookies the client sends
				*/

				if (p == NULL){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: P IS NULL [%s]", p);
				}else
				{
					if(config->session_store_free_cookies){
						re = pcre_compile(config->session_store_free_cookies, 0, &error, &error_offset, NULL);

						if (re == NULL) {
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: return code of pcre_compile in Cookie Store is NULL");
						}

						rc = pcre_exec(re, NULL, p, strlen(p), 0, 0, re_vector, 3072);


						if (rc < 0) {
							ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: REQUEST FILTER: INVALID COOKIE SENT BY CLIENT (POTENTIALLY HACKING ATTEMPT) [%s]", p);
						}


						if (rc == 0) {
							ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: PCRE output vector too small (%d)", 3072/3-1);
							ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: Problems with the following ARGS = %s", value);
							return DECLINED;
						}

						if (rc > 0) {
							ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: REQUEST FILTER: FREE COOKIE FOUND [%s]", p);
							/*
								Please note, apr_table_unset(r->hearders_in, "Cookie") was done in mod_but.c (CORE)
								Here we add our "wanted" cookies again into the request header.
							*/

							insert_cookie = (char *)apr_psprintf(r->pool, "%s;", p);
							existing_cookie = apr_table_get(r->notes, "REQUEST_COOKIES"); 
					
							if (insert_cookie != NULL){
								if (apr_table_get(r->notes, "REQUEST_COOKIES") == NULL) {
									new_cookie=apr_pstrcat(r->pool, insert_cookie, NULL);
					
								} else {
									new_cookie=apr_pstrcat(r->pool, existing_cookie, insert_cookie, NULL);
									
								}
								apr_table_set(r->notes, "REQUEST_COOKIES", new_cookie);
								ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: ADD COOKIE [%s] into r->notes", apr_table_get(r->notes, "REQUEST_COOKIES"));
							}

							//apr_table_addn(r->headers_in, "Cookie", "dummycookie=dummy;" );
						}
					}
				}
			}

		}
	}
	return DECLINED;
}




int mod_but_analyze_request_headers(void *result, const char *key, const char *value){

	cookie_res * cr = (cookie_res *) result;
	request_rec *r = cr->r;
	mod_but_server_t *config;

	ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: REQUEST_FILTER: ANALYZE REQUEST HEADER [%s] [%s]", key, value);
	config = ap_get_module_config(r->server->module_config, &but_module);


	if(key){
		pcre *re;  					// the regular expression
		const char *error;				// error text for the failed regex compilation
		int error_offset;				// offset of the regex compilation error, if any
		int rc = 0;					// return code of pcre_exec
		int re_vector[3072];

		re = pcre_compile("cOOkIe", PCRE_CASELESS, &error, &error_offset, NULL);

		if (re == NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: return code of pcre_compile in Cookie Store is NULL");
		}

		rc = pcre_exec(re, NULL, key, strlen(key), 0, 0, re_vector, 3072);

		
		if (rc < 0) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: Cookie was not in ARGS = %s", key);
		}
		

		if (rc == 0) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: PCRE output vector too small (%d)", 3072/3-1);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: Problems with the following ARGS = %s", key);
			return DECLINED;
		}

		if (rc > 0) {
			int frh;
			/*
				If we are here, the Client has sent some cookies
			*/
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_request_filter.c: REQUEST FILTER: FOUND COOKIE IN REQUEST FROM CLIENT [%s] [%s]", key, value);
			// Example for value [MOD_BUT=qG4MPxyGMWLzIgQ1VjE9]
			frh=filter_request_headers(r, value);
			return frh;
		}
	}
	return DECLINED;
}
