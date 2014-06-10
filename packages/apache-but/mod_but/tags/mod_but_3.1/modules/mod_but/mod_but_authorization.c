/*#############################################
#
# Title:        mod_but_authorization.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
#include "mod_but.h"

int do_authorization(int shm_offset_number, request_rec *r){

       pcre *re = NULL;  					// the regular expression
       const char *error;				// error text for the failed regex compilation
       int error_offset;				// offset of the regex compilation error, if any
       int rc = 0;					// return code of pcre_exec
       int re_vector[3072];

	mod_but_dir_t *dconfig = ap_get_module_config(r->per_dir_config, &but_module);
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
	if (dconfig == NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: Illegal Directory Config");
	}

	if(dconfig->logon_required){
		/*
			If we are here, LOGON required is somehow configured (On, Off or some other value)
		*/
		if (!apr_strnatcmp(dconfig->logon_required, "Off")){
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: MOD_BUT_LOGON_REQUIRED is turned OFF for this Location");
			return 7702;
		}

		if (!apr_strnatcmp(dconfig->logon_required, "On")){
			static apr_rmm_t *cs_rmm;
			static apr_rmm_off_t *off;
			mod_but_cookie *c;
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: MOD_BUT_LOGON_REQUIRED is turned ON for this Location");
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: We will check for proper authentication");
			cs_rmm = NULL;
			off = NULL;

			cs_rmm = find_cs_rmm();
			off = find_cs_rmm_off();
			c = apr_rmm_addr_get(cs_rmm, off[shm_offset_number]);

			if (c->logon_state == 0){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: Client not logged in yet (c->logon_state == 0)");
				return 7700; // client not logged in yet
			}

			if (c->logon_state == 1){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: Client is logged in successfully (c->logon_state == 1)");
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: MOD_BUT_LOGON_REQUIRED is configured: Client is logged in successfully (c->logon_state == 1)");
				if(config->service_list_enabled_on){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization: service list check is on");
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization: service list access regexp: %s", c->service_list);
					

					if(c->service_list != NULL){
						re = pcre_compile(c->service_list, 0, &error, &error_offset, NULL);
					}else{
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: c->service_list PCRE FREE URL STRING IS NULL");
					}
					
					
					if (re == NULL) {
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: service_list return code of pcre_compile is NULL");
					}
					
					rc = pcre_exec(re, NULL, r->uri, strlen(r->uri), 0, 0, re_vector, 3072);

					if (rc < 0) {
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: service_list PCRE ERROR NOMATCH");
						return 7703; // client is properly authenticated, but not authorized
					}
					
					if (rc == 0) {
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: service_list PCRE output vector too small (%d)", 3072/3-1);
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: service_list Problems with the following URI = %s", r->uri);
						// returen DECLINED;
						return 7706;
					}
					
					if (rc > 0) {
						ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: service list PCRE MATCHED!!!");
					}
				}else{
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization: service list check is off");
				}

				/*
					User is authorized from the uri point of view: Need to check, if the user has the correct auth_level for the requesting uri
				
				*/
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: httpd.conf AUTH_STRENGTH is [%d]", dconfig->mod_but_auth_strength);
				ap_log_rerror(PC_LOG_INFO, r, "mod_but: session AUTH_STRENGTH is [%d]", c->auth_strength);

				if(c->auth_strength >= dconfig->mod_but_auth_strength){
					// do nothing
					ap_log_rerror(PC_LOG_INFO, r, "mod_but: session auth_strength >= required httpd.conf auth_strength");
				} else {
					if (dconfig->mod_but_auth_strength == 1) {
						ap_log_rerror(PC_LOG_INFO, r, "mod_but: redirect to 1");
						return 7704;  // client redirect to setup login window
					}
					if (dconfig->mod_but_auth_strength == 2) {
						ap_log_rerror(PC_LOG_INFO, r, "mod_but: redirect to 2");
						return 7705;  // client redirect to setup login window
					}			
				} 

				return 7701; // client is properly authenticated
			}
		}
	}else{
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: MOD_BUT_LOGON_REQUIRED is not defined for this URL");
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: MOD_BUT_LOGON_REQUIRED: authentication not required for this URL");
		return 7702; // authentication is not required for this url	
	}
	return OK;
}

