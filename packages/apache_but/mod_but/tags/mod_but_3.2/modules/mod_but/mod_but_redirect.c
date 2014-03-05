/*#############################################
#
# Title:        mod_but_redirect.c
# Author:       daniel.roethlisberger@csnc.ch
# Date:         2008-05-30
# Version:      3.2
#
#############################################*/
/* $Id: mod_but_redirect.c 61 2008-05-30 14:26:54Z droethli $ */

#include "mod_but.h"

/*
 * Redirect to a relative URI.  Adds a Location header to the request and returns the
 * appropriate HTTP response code.
 *
 * This function directly returns HTTP error codes, so the correct way to call it is:
 *    return mod_but_redirect_to_relurl(r, uri);
 */
int
mod_but_redirect_to_relurl(request_rec *r, const char *relurl)
{
	const char *url, *host;
	apr_port_t port;

	if (!relurl) {
		ERRLOG_CRIT("Redirection to NULL attempted!");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/*
	 * Check for CR/LF injection; if we still have unencoded newlines or
	 * carriage returns in relurl here, deny the redirection.
	 * This is a last resort against HTTP Response Splitting attacks.
	 * If we still have CR/LF characters here, then that would be a bug
	 * in the calling code which must be fixed.
	 */
	switch (mod_but_regexp_match(r, "[\r\n]", relurl)) {
	case STATUS_MATCH:
		ERRLOG_CRIT("ATTACK: relurl contains raw CR/LF characters [%s]", relurl);
		ERRLOG_CRIT("This is a bug in mod_but - CR/LF chars should be encoded!");
		return HTTP_INTERNAL_SERVER_ERROR;
	case STATUS_NOMATCH:
		ERRLOG_INFO("r->uri does not contain CR/LF [%s]", r->uri);
		break;
	case STATUS_ERROR:
	default:
		ERRLOG_CRIT("Error while matching CRLF");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	port = ap_get_server_port(r);
	if ((port != DEFAULT_HTTP_PORT) && (port != DEFAULT_HTTPS_PORT)) {
		/* because of multiple passes through don't use r->hostname() */
		host = apr_psprintf(r->pool, "%s:%d", ap_get_server_name(r), port);
	} else {
		host = apr_psprintf(r->pool, "%s", ap_get_server_name(r));
	}
	url = apr_psprintf(r->pool, "%s://%s%s", ap_http_method(r), host, relurl);

	apr_table_setn(r->err_headers_out, "Location", url);
	r->content_type = NULL;

	return HTTP_MOVED_TEMPORARILY;
}


/*
 * Redirect to cookie test next stage, or cookie refused URL.
 *
 * This function directly returns HTTP error codes, so the correct way to call it is:
 *    return mod_but_handle_shm_error(r);
 */
int
mod_but_redirect_to_cookie_test(request_rec *r, mod_but_server_t *config)
{
	int cookie_try, i;
	char *target_uri;

	/*
	 * Get cookie try argument and redirect to next cookie_try stage.
	 * If cookie_try >= 3, redirect to the cookie refused error page.
	 */
	cookie_try = mod_but_find_cookie_try(r);
	if (cookie_try < 0) {
		ERRLOG_CRIT("Cookie Test Error [%d]", cookie_try);
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	if (cookie_try >= 3) {
		return mod_but_redirect_to_relurl(r, config->client_refuses_cookies_url);
	}

	cookie_try++;
	ERRLOG_CRIT("Redirecting to cookie test stage %s=%d", MOD_BUT_COOKIE_TRY, cookie_try);

	/*
	 * Strip all GET parameters from r->unparsed_uri,
	 * append the cookie_try parameter, and redirect.
	 */
	target_uri = apr_pstrdup(r->pool, r->unparsed_uri);
	if (target_uri == NULL) {
		ERRLOG_CRIT("Out of memory");
		return HTTP_INTERNAL_SERVER_ERROR;
	}
	for (i = strlen(target_uri); i > 0; i--) {
		if (target_uri[i] == '?') {
			target_uri[i] = '\0';
		}
	}
	ERRLOG_INFO("r->uri=[%s] r->unparsed_uri=[%s] target_uri=[%s]", r->uri, r->unparsed_uri, target_uri);
	return mod_but_redirect_to_relurl(r, apr_psprintf(r->pool, "%s?%s=%d", target_uri, MOD_BUT_COOKIE_TRY, cookie_try));
}


/*
 * Handle an out of SHM memory condition by redirecting the user to the error page,
 * if available, or generating an internal server error.
 *
 * This function directly returns HTTP error codes, so the correct way to call it is:
 *    return mod_but_handle_shm_error(r);
 */
int
mod_but_redirect_to_shm_error(request_rec *r, mod_but_server_t *config)
{
	ERRLOG_INFO("All SHM space used!");

	apr_table_unset(r->headers_out, "Set-Cookie");
	apr_table_unset(r->err_headers_out, "Set-Cookie");

	if (config->all_shm_space_used_url == NULL) {
		ERRLOG_INFO("MOD_BUT_ALL_SHM_SPACE_USED_URL not configured in httpd.conf");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return mod_but_redirect_to_relurl(r, config->all_shm_space_used_url);
}

