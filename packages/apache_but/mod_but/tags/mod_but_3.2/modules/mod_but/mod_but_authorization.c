/*#############################################
#
# Title:        mod_but_authorization.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
/* $Id: mod_but_authorization.c 58 2008-05-30 14:05:14Z droethli $ */

#include "mod_but.h"

/*
 * Check request authorization.
 *
 * Returns:
 * STATUS_ELOGIN	client not logged in yet
 * STATUS_OK		client is properly authorized or no authorization required
 * STATUS_EDENIED	client is properly authenticated, but not authorized
 * STATUS_ESTEPUP1	client is properly authenticated, but with too low auth_strength (1)
 * STATUS_ESTEPUP2	client is properly authenticated, but with too low auth_strength (2)
 * STATUS_ERROR		internal error
 */
apr_status_t
mod_but_do_authorization(request_rec *r, int shm_offset)
{
	apr_rmm_t *cs_rmm;
	apr_rmm_off_t *off;
	mod_but_cookie *c;
	mod_but_dir_t *dconfig = ap_get_module_config(r->per_dir_config, &but_module);
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	if (!dconfig) {
		ERRLOG_CRIT("Illegal Directory Config");
		return STATUS_ERROR;
	}

	if (!dconfig->logon_required) {
		ERRLOG_INFO("Logon not required for this directory");
		return STATUS_OK;
	}

	ERRLOG_INFO("MOD_BUT_LOGON_REQUIRED enabled, checking authentication and authorization");

	cs_rmm = find_cs_rmm();
	off = find_cs_rmm_off();
	c = apr_rmm_addr_get(cs_rmm, off[shm_offset]);

	if (c->logon_state == 0) {
		ERRLOG_INFO("Client not logged in yet (c->logon_state == 0)");
		return STATUS_ELOGIN;
	}

	if (c->logon_state == 1) {
		ERRLOG_INFO("Client is logged in successfully (c->logon_state == 1)");
		ERRLOG_INFO("MOD_BUT_LOGON_REQUIRED is configured: Client is logged in successfully (c->logon_state == 1)");
		if (config->service_list_enabled_on) {
			ERRLOG_INFO("service list check is on, list is [%s]", c->service_list);
			if(c->service_list == NULL) {
				ERRLOG_CRIT("Service list check enabled but service list not set");
				return STATUS_ERROR;
			}

			/* match URL against service list */
			switch (mod_but_regexp_match(r, c->service_list, r->uri)) {
			case STATUS_MATCH:
				ERRLOG_INFO("service_list matched: pass through");
				break;
			case STATUS_NOMATCH:
				ERRLOG_CRIT("Access denied - service_list did not match");
				return STATUS_EDENIED;
			case STATUS_ERROR:
			default:
				ERRLOG_CRIT("Error while matching service_list");
				return STATUS_ERROR;
			}
		} else {
			ERRLOG_INFO("service list check is off");
		}

		/*
		 * User is authorized from the uri point of view: Need to check, if the user has the correct auth_level for the requesting uri
		 */
		ERRLOG_INFO("Authentication strength from httpd.conf [%d] from session [%d]", dconfig->mod_but_auth_strength, c->auth_strength);
		if (c->auth_strength >= dconfig->mod_but_auth_strength) {
			ERRLOG_INFO("session auth_strength >= required httpd.conf auth_strength");
			return STATUS_OK;
		} else {
			if (dconfig->mod_but_auth_strength == 1) {
				ERRLOG_INFO("redirect to login 1");
				return STATUS_ESTEPUP1;
			}
			if (dconfig->mod_but_auth_strength == 2) {
				ERRLOG_INFO("redirect to login 2");
				return STATUS_ESTEPUP2;
			}
			return STATUS_ERROR;
		}
		/* not reached */
	}

	ERRLOG_CRIT("Unexpected value of logon state [%d]", c->logon_state);
	return STATUS_ERROR;
}
