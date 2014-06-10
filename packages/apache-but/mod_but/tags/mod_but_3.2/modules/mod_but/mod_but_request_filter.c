/*#############################################
#
# Title:        mod_but_request_filter.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
/* $Id: mod_but_request_filter.c 53 2008-05-29 15:18:29Z droethli $ */

#include "mod_but.h"

/*
 * Request header filter called via apr_table_do() on all "Cookie" headers.
 *
 * We copy all cookies we want to keep into r->notes (mod_but session and free cookies).
 * Cookies are sent in a single line from the browser Cookie: jsessionid=1234; foo=3322;
 *
 * Returns TRUE to continue iteration, FALSE to stop iteration.
 */
int
mod_but_filter_request_cookies(void *result, const char *key, const char *value) {
	cookie_res * cr = (cookie_res *) result;
	request_rec *r = cr->r;

	const char *insert_cookie = NULL;
	const char *new_cookie = NULL;
	const char *existing_cookie = NULL;

	char *qa, *p, *last;

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	if (!value || !key || !config) {
		ERRLOG_CRIT("Value, key or config are NULL!");
		return FALSE;
	}

	ERRLOG_INFO("config->cookie_name=[%s] value=[%s] key=[%s]", config->cookie_name, value, key);

	qa = apr_pstrdup(r->pool, value);
	if (!qa) {
		ERRLOG_CRIT("Out of memory");
		return FALSE;
	}

	for (p = apr_strtok(qa, "; ", &last); p != NULL; p = apr_strtok(NULL, "; ", &last)) {
		char *p1 = strstr(p, config->cookie_name);
		if (p1) {
			/* session cookie */
			ERRLOG_INFO("Found a mod_but session cookie: [%s]", p1);
			p1 += strlen(config->cookie_name);
			if (*p1 == '=') {
				char *mod_but_session = apr_pstrdup(r->pool, p1+1);
				ERRLOG_INFO("Adding session cookie [%s] into r->notes[%s]", mod_but_session, config->cookie_name);
				apr_table_set(r->notes, config->cookie_name, mod_but_session);
				continue;
			}
		}

		/* not a session cookie */
		if (config->session_store_free_cookies) {
			switch (mod_but_regexp_match(r, config->session_store_free_cookies, p)) {
			case STATUS_MATCH:
				ERRLOG_INFO("Found a free cookie: [%s]", p);
				insert_cookie = apr_psprintf(r->pool, "%s; ", p);
				if (!insert_cookie) {
					ERRLOG_CRIT("Out of memory!");
					return FALSE;
				}
				existing_cookie = apr_table_get(r->notes, "REQUEST_COOKIES");
				if (existing_cookie == NULL) {
					new_cookie = apr_pstrdup(r->pool, insert_cookie);
				} else {
					new_cookie = apr_pstrcat(r->pool, existing_cookie, insert_cookie, NULL);
				}
				ERRLOG_INFO("Adding cookie [%s] into r->notes[REQUEST_COOKIES]", new_cookie);
				apr_table_set(r->notes, "REQUEST_COOKIES", new_cookie);
				break;
			case STATUS_NOMATCH:
				ERRLOG_CRIT("Warning: Client sent unexpected cookie [%s] - hacking attempt?", p);
				break;
			case STATUS_ERROR:
			default:
				ERRLOG_CRIT("Error matching free cookie regexp (value=[%s])", value);
				return FALSE;
			}
		} else {
			ERRLOG_INFO("No free cookie URLs configured");
		}
	}

	ERRLOG_INFO("mod_but_filter_request_cookies() ended normally");
	return TRUE;
}

