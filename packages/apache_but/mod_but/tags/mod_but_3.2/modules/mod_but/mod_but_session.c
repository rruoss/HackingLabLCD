/*#############################################
#
# Title:        mod_but_session.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
/* $Id: mod_but_session.c 63 2008-05-30 15:33:20Z droethli $ */

#include "mod_but.h"

/*
 * Generate a new session ID.
 *
 * Note that apr_generate_random_bytes() blocks on Linux due to reading from
 * /dev/random.  FreeBSD /dev/random never blocks.  Solaris /dev/random does
 * not seem to block either.  To keep mod_but usable on Linux, we try to not
 * waste any randomness: only read as much as needed and use all bits.
 * On Linux, APR should be compiled to read from /dev/urandom by default.
 */
char *
generate_session_id(request_rec *r)
{
	apr_status_t rc;
	unsigned char rnd[MOD_BUT_SIDBYTES];
	char *sid = apr_pcalloc(r->pool, apr_base64_encode_len(MOD_BUT_SIDBYTES) + 1);

	if (!sid) {
		ERRLOG_CRIT("FATAL: Out of memory");
		return NULL;
	}

	if (APR_SUCCESS != (rc = apr_generate_random_bytes(rnd, MOD_BUT_SIDBYTES))) {
		ERRLOG_CRIT("FATAL: apr_generate_random_bytes returned %d", rc);
		return NULL;
	}

	if (0 >= apr_base64_encode_binary(sid, rnd, MOD_BUT_SIDBYTES)) {
		ERRLOG_CRIT("FATAL: apr_base64_encode failed");
		return NULL;
	}

	ERRLOG_INFO("Session ID generated [%s]", sid);
	return sid;
}

/*
 * Builds the session cookie from the given session ID and configuration.
 */
char *
build_cookie(request_rec *r, mod_but_server_t *config, char *sid)
{
	char *cookie = NULL;
	const char *cookiename = config->cookie_name;
	const char *domain = "";
	const char *path = "";
	const char *secure = "";
	const char *httponly = "";
	const char *expiration = "";

	if (apr_strnatcmp(config->cookie_domain, "")) {
		domain = apr_psprintf(r->pool, "domain=%s; ", config->cookie_domain);
	}

	if (apr_strnatcmp(config->cookie_path, "")) {
		path = apr_psprintf(r->pool, "path=%s; ", config->cookie_path);
	}

	if (config->cookie_secure == 1) {
		secure = "secure; ";
	}

	if (config->cookie_httponly == 1) {
		httponly = "HttpOnly";
	}

	if (apr_strnatcmp(config->cookie_expiration, "")) {
		expiration = apr_psprintf(r->pool, "expires=%s; ", config->cookie_expiration);
	}

	cookie = apr_psprintf(r->pool, "%s=%s; %s%s%s%s%s", cookiename, sid, domain, path, expiration, secure, httponly);
	ERRLOG_INFO("Built cookie string [%s]", cookie);
	return cookie;
}

/*
 * a) Generate new Session ID
 * b) Copies the Session as Set-Cookie into the response header field
 * c) Creates the required structures in the shared memory segment
 *
 * Will set Set-Cookie headers via the apr_table_t *headers_out, which can
 * be r->headers_out or r->err_headers_out.
 */
apr_status_t
create_new_mod_but_session(request_rec *r, apr_table_t *headers_out, int *shmoffset)
{
	apr_status_t rc;
	char *cookie = NULL, *sid = NULL;
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	ERRLOG_INFO("Creating new mod_but session");

	sid = generate_session_id(r);
	if (sid == NULL) {
		ERRLOG_CRIT("Failed to generate session ID");
		return STATUS_ERROR;
	}

	/*
	 * Create a new "session" into the shared memory segment
	 */
	cleaning_shm_from_expired_session(r);
	cleaning_shm_history_from_expired_session(r);
	rc = create_new_shm_session(r, sid, shmoffset);
	if (rc != STATUS_OK) {
		ERRLOG_CRIT("Failed to create new SHM session");
		return rc;
	}
	ERRLOG_INFO("Created session at SHM offset [%d]", *shmoffset);

	cookie = build_cookie(r, config, sid);
	if (cookie == NULL) {
		ERRLOG_CRIT("Failed to build cookie");
		return STATUS_ERROR;
	}

	apr_table_setn(headers_out, "Set-Cookie", cookie);
	ERRLOG_INFO("Set-Cookie: [%s]", cookie);
	return STATUS_OK;
}

/*
 * Function returns integer value (shmoffset), if the session is found in the shm section
 */
apr_status_t
mod_but_validate_session(request_rec *r, int *shmoffset)
{
	int i;
	int y = 0;

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	apr_rmm_t *cs_rmm = find_cs_rmm();
	apr_rmm_off_t *off = find_cs_rmm_off();
	apr_rmm_t *cs_rmm_history = find_cs_rmm_history();
	apr_rmm_off_t *off_history = find_cs_rmm_off_history();

	/*
	 * Cleanup Function (delete *old* sessions from shm)
	 */

	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
		/*
		 * Lets go through the shm to find out, if the session is in our shm store
		 */
		mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[i]);
		if (!apr_strnatcmp(c->session_value, apr_table_get(r->notes, config->cookie_name))) {
			apr_time_t curtime;
			int tnow;
			int tcreate;
			int tlastaccess;

			/*
			 * If we are here, the client has sent a mod_but session
			 */
			ERRLOG_INFO("Found session at SHM [%d]", i);
			curtime = apr_time_now();
			tnow = (int)apr_time_sec(curtime);
			tcreate = c->session_create_time;
			tlastaccess = c->session_last_access_time;

			if ((tnow - tcreate) > config->session_timeout) {
				ERRLOG_INFO("Delta between tnow and tcreate %d", tnow-tcreate);
				ERRLOG_CRIT("Deleting - session timeout reached at SHM [%d]", i);
				mod_but_delete_session(i, r);
				return STATUS_ETIMEOUT;
			} else if ((tnow - tlastaccess) > config->session_inactivity_timeout) {
				ERRLOG_INFO("Delta between tnow and tlastaccess %d", tnow-tlastaccess);
				ERRLOG_CRIT("Deleting - inactivity timeout reached at SHM [%d]", i);
				mod_but_delete_session(i, r);
				return STATUS_EINACTIVE;
			} else {
				ERRLOG_INFO("Delta between tnow and tlastaccess %d", tnow-tlastaccess);
				ERRLOG_INFO("Updating access time of session at SHM [%d]", i);
				c->session_last_access_time = tnow;
			}

			// if we are here, the session is valid, and not timed out yet, so we return the shmoffset
			ERRLOG_INFO("Verified session at SHM [%d]", i);
			*shmoffset = i;
			return STATUS_OK;
		}
	}

	// In this case, the sent session by the client is invalid, guessed, hacked or in the history

	for (y = 0; y < MOD_BUT_SESSION_HISTORY_COUNT; y++) {
		mod_but_cookie_history *c_history = apr_rmm_addr_get(cs_rmm_history, off_history[y]);
		if (!apr_strnatcmp(c_history->session_value, apr_table_get(r->notes, config->cookie_name))) {
			ERRLOG_INFO("Client Session found in SHM HISTORY %s", c_history->session_value);
			return STATUS_ETIMEOUT;
		}
	}

	/*
	 * If we are here, the session is not in the normal SHM or in the History SHM. It must be a tamper attempt
	 */
	ERRLOG_INFO("Hacking attempt [%s]", apr_table_get(r->notes, config->cookie_name));
	return STATUS_EHACKING;
}


/*
 * Delete session in session shm store
 * Delete everything in history shm store
 * Delete everything in cookie shm store
 *
 * XXX rewrite this (SHM)
 */
apr_status_t
mod_but_delete_session(int shmoff, request_rec *r) {
	int i;

	apr_rmm_t *cs_rmm = find_cs_rmm();
	apr_rmm_off_t *off = find_cs_rmm_off();
	apr_rmm_t *cs_rmm_history = find_cs_rmm_history();
	apr_rmm_off_t *off_history = find_cs_rmm_off_history();

	mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[shmoff]);

	for (i = 0; i < MOD_BUT_SESSION_HISTORY_COUNT; i++) {
		mod_but_cookie_history *c_history = apr_rmm_addr_get(cs_rmm_history, off_history[i]);

		/*
		 * Searching an empty place in the history shm store and copy the session_value to the history
		 */
		if (!apr_strnatcmp(c_history->session_value, "empty")) {
			/*
			 * If we are here, we have found an empty history shm place and backup
			 * the deleting session into the history store
			 */
			apr_cpystrn(c_history->session_value, c->session_value, sizeof(c_history->session_value));
			c_history->session_delete_time = (int)apr_time_sec(apr_time_now());
			ERRLOG_INFO("Make history of session %s at history SHM offset %d", c_history->session_value, i);

			/*
			 * Now we have a backup of the session value in the history.
			 * The next step will delete the session in the session shm store to make it free for others
			 */
			apr_cpystrn(c->session_name, "empty", sizeof(c->session_name));
			apr_cpystrn(c->session_value, "empty", sizeof(c->session_value));
			apr_cpystrn(c->session_firsturl, "empty", sizeof(c->session_firsturl));
			c->logon_state = 0;
			c->logon_flag = 0;
			c->auth_strength = 0;
			apr_cpystrn(c->orig_url_before_logon, "empty", sizeof(c->orig_url_before_logon));
			apr_cpystrn(c->service_list, "empty", sizeof(c->service_list));

			if (c->link_to_cookiestore == -1) {
				ERRLOG_INFO("There is nothing in the cookie store to delete");
			} else {
				ERRLOG_INFO("Start DELETING cookiestore headers at CS offset %d", c->link_to_cookiestore);
				delete_cookiestore_entries_belonging_to_a_deleting_session(r, c->link_to_cookiestore);
			}
			return STATUS_OK;
		}
	}

	/*
	 * If we are here, there was no space left in the SHM history. This is a PROBLEM.
	 * We will delete the session without doing history, but we have at least a log entry
	 */
	apr_table_setn(r->notes, "HISTORY_SHM" , "PROBLEM");
	ERRLOG_INFO("(SHM HISTORY) All SHM HISTORY is used - Unable to make history of session");

	apr_cpystrn(c->session_name, "empty", sizeof(c->session_name));
	apr_cpystrn(c->session_value, "empty", sizeof(c->session_value));
	apr_cpystrn(c->session_firsturl, "empty", sizeof(c->session_firsturl));

	if (c->link_to_cookiestore == -1) {
		ERRLOG_INFO("There is nothing in the cookie store to delete");
	} else {
		ERRLOG_INFO("Start DELETING cookiestore headers at CS offset %d", c->link_to_cookiestore);
		delete_cookiestore_entries_belonging_to_a_deleting_session(r, c->link_to_cookiestore);
	}
	return STATUS_OK;
}

/*
 * Renew session.
 *
 * Create a new session, copy details from old session to new
 * session, and delete the old session.
 */
apr_status_t
renew_mod_but_session(request_rec *r, int shmoffold, int *shmoffnew)
{
	apr_status_t rc;
	apr_rmm_t *cs_rmm = find_cs_rmm();
	apr_rmm_off_t *off = find_cs_rmm_off();
	mod_but_server_t *config;
	mod_but_cookie *c_old;
	mod_but_cookie *c_new;

	ERRLOG_INFO("Renewing sesssion");

	config = ap_get_module_config(r->server->module_config, &but_module);
	c_old = apr_rmm_addr_get(cs_rmm, off[shmoffold]);

	rc = create_new_mod_but_session(r, r->headers_out, shmoffnew);
	if (rc != STATUS_OK) {
		ERRLOG_CRIT("Failed to create new session");
		return rc;
	}

	c_new = apr_rmm_addr_get(cs_rmm, off[*shmoffnew]);
	c_new->session_create_time = c_old->session_create_time;
	c_new->session_last_access_time = c_old->session_last_access_time;
	c_new->link_to_cookiestore = c_old->link_to_cookiestore;
	c_new->logon_state = c_old->logon_state;
	c_new->logon_flag = c_old->logon_flag;
	c_new->auth_strength = c_old->auth_strength;
	apr_cpystrn(c_new->orig_url_before_logon, c_old->orig_url_before_logon, sizeof(c_new->orig_url_before_logon));
	apr_cpystrn(c_new->service_list, c_old->service_list, sizeof(c_new->service_list));
	c_old->link_to_cookiestore = -1;

	rc = mod_but_delete_session(shmoffold, r);
	if (rc != STATUS_OK) {
		ERRLOG_CRIT("Failed to delete old session");
		return rc;
	}

	return STATUS_OK;
}

