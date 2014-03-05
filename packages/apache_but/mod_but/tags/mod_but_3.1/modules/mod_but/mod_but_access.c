/*#############################################
#
# Title:        mod_but_access.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/

#include "mod_but.h"

/*
	This functions will find out, if the URI contains a __cookie_try parameter. This
	is important in the very beginning of a mod_but session, while we are trying to
	find out, if the client has cookie support enabled. 

	return = 0	no __cookie_try in URL
	return = 1	there is a __cookie_try in URL

*/
void find_cookie_try(request_rec *r)
{
    apr_status_t ret = 0;
    char *p = strstr(r->args, "__cookie_try");

    if(p)
    {
      p += strlen("__cookie_try");

      if(*p == '=')
      {
        char *cid = (char *)apr_pstrdup(r->pool, p+1);
        if(cid)
        {
          p = strchr(cid, '&');
          if(p)
            *p = '\0';
          apr_table_set(r->notes, "COOKIE_TRY" , cid);
          ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: COOKIE_TRY IS %s", apr_table_get(r->notes, "COOKIE_TRY"));
          ret = 1;
        }
      }
    }

  if(!ret) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: PROBLEM");
  }
}





/*

	Return Code 9900: 		Cookie_try was not in query
	Return Code 9901:		Cookie_TRY 1 in argument
	Return Code 9902:		Cookie_TRY 2 in argument
	Return Code 9903:		Cookie_TRY 3 in argument

*/
int analyze_request_arguments_for_cookie_test(request_rec *r)
{
       apr_status_t rc = 0;

       pcre *re = apr_pcalloc(r->pool, 64);         // the regular expression
       const char *error = apr_pcalloc(r->pool, 64);    // error text for the failed regex compilation
       int error_offset;                                // offset of the regex compilation error, if any
       int re_vector[3072];

	ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: r->args ist %s", r->args);

	
	if ((r->args == NULL)&&(r->main != NULL)&&(r->main->args != NULL)) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: r->main->args ist %s", r->main->args);
	}

	if(r->args==NULL)
	{
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: r->args ist NULL");
		rc = 9900;
		return rc;
	}else
	{
      		re = pcre_compile("(__cookie_try)", 0, &error, &error_offset, NULL);
	        ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: analyze_request_arguments_for_cookie_test executed");
      		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: arguments are: %s", r->args);

		if (re == NULL) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: return code of pcre_compile is NULL");
		}

		rc = pcre_exec(re, NULL, r->args, strlen(r->args), 0, 0, re_vector, 3072);

		if (rc < 0) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: __cookie_try was not in ARGS = %s", r->args);
			rc = 9900;
			return rc;
		}

		if (rc == 0) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: PCRE output vector too small (%d)", 3072/3-1);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: Problems with the following ARGS = %s", r->args);
			return 9904;
		}

		/* 
		
			If we are here, the query arguments contain something like "__cookie_try" in it. 
			
		*/
		if (rc > 0) {
			find_cookie_try(r);

	                if(!strcmp(apr_table_get(r->notes, "COOKIE_TRY"), "1")) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: __cookie_try is in ARGS = %s", r->args);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: __cookie_try is in ARGS = %s", apr_table_get(r->notes, "COOKIE_TRY"));
			rc = 9901;
			return rc;
			}
			
			if(!strcmp(apr_table_get(r->notes, "COOKIE_TRY"), "2")) {
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: __cookie_try is in ARGS = %s", r->args);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: __cookie_try is in ARGS = %s", apr_table_get(r->notes, "COOKIE_TRY"));
			rc = 9902;
			return rc;
			}

                        if(!strcmp(apr_table_get(r->notes, "COOKIE_TRY"), "3")) {
                        ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: __cookie_try is in ARGS = %s", r->args);
                        ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: __cookie_try is in ARGS = %s", apr_table_get(r->notes, "COOKIE_TRY"));
                        rc = 9903;
                        return rc;
                        }

			rc = 9900;
			return rc;

		}

	}
	return OK;
}


int analyze_request_uri_for_session_destroy(request_rec *r)
{
	apr_status_t rc = 0;
	pcre *re = apr_pcalloc(r->pool, 64);         // the regular expression
	const char *error = apr_pcalloc(r->pool, 64);    // error text for the failed regex compilation
	int error_offset;                                // offset of the regex compilation error, if any
	int re_vector[3072];
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
       
       if(config->session_destroy != NULL)
       {
       		re = pcre_compile(config->session_destroy, 0, &error, &error_offset, NULL);
	}else{
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: SESSION DESTROY STRING IS NULL");
	}
       
	if (re == NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: return code of pcre_compile is NULL");
	}

	rc = pcre_exec(re, NULL, r->uri, strlen(r->uri), 0, 0, re_vector, 3072);

	if (rc < 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: destroy pattern was not in URI = %s", r->uri);
		rc = 8800;
		return rc;
	}

	if (rc == 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: PCRE output vector too small (%d)", 3072/3-1);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: Problems with the following URI = %s", r->uri);
		rc = 8801;
		return rc;
	}

	/* 
	
		If we are here, the uri arguments contains the destroy pattern
		
	*/
	if (rc > 0) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_access.c: Destroy pattern is in URI");
		rc = 8802;
		return rc;
	}
	return OK;
}




