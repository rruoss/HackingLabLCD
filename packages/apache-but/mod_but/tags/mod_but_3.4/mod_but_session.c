/* $Id: mod_but_session.c 147 2010-05-30 20:28:01Z ibuetler $ */

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
static char *
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

	return sid;
}

/*
 * Initialize session_t data structure with invalid session.
 */
void
but_session_init(session_t *session, request_rec *r, mod_but_server_t *config)
{
	session->handle = INVALID_SESSION_HANDLE;
	session->data = NULL;
	session->request = r;
	session->config = config;
}

/*
 * Returns true if handle is INVALID_SESSION_HANDLE or data doesn't point to a
 * session slot.
 */
int
but_session_isnull(session_t *session)
{
	return !session || !session->data || session->handle == INVALID_SESSION_HANDLE;
}

/*
 * Find a session by session name and ID.
 * session is an initialized session_t.
 */
apr_status_t
but_session_find(session_t *session, const char *session_name, const char *session_id)
{
	int i;

	/* loop over all sessions */
	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
		session_data_t *session_data = get_session_by_index(i); /* XXX iterator in SHM code */
		if (session_data->slot_used &&
		    !apr_strnatcmp(session_data->session_id, session_id) &&   /* id is more likely to mismatch */
		    !apr_strnatcmp(session_data->session_name, session_name)) {
			session->handle = i;
			session->data = session_data;
			return STATUS_OK;
		}
	}
	return STATUS_ENOEXIST;
}

/*
 * Open a session by session handle.
 * session is an initialized session_t.
 */
apr_status_t
but_session_open(session_t *session, session_handle_t handle)
{
	session->data = get_session_by_index(handle);
	if (!session->data->slot_used) {
		session->data = NULL;
		session->handle = INVALID_SESSION_HANDLE;
		return STATUS_ERROR;
	}
	session->handle = handle;
	return STATUS_OK;
}

/*
 * Create new session and store it in the SHM segment.
 * Caller must set up cookies.
 * session is an initialized session_t.
 */
apr_status_t
but_session_create(session_t *session)
{
	apr_status_t status;
	char *sid = NULL;

	sid = generate_session_id(session->request);
	if (!sid) {
		return STATUS_ERROR;
	}

	status = create_new_shm_session(session->request, sid, &session->handle);
	if (status != STATUS_OK) {
		return status;
	}
	session->data = get_session_by_index(session->handle);
	return STATUS_OK;
}

/*
 * Delete session from session store.
 * session is a valid session which gets invalidated.
 */
void
but_session_unlink(session_t *session)
{
	if (but_session_isnull(session)) {
		return;
	}
	but_shm_free(session->data);
	session->data = NULL;
	session->handle = INVALID_SESSION_HANDLE;
}

/*
 * Validate a session.  If session has reached any timeouts, it is deleted.
 * session is a valid session which may get invalidated.
 * Returns
 * STATUS_OK		session ok
 * STATUS_ENOEXIST	session reached a timeout or is invalid
 */
apr_status_t
but_session_validate(session_t *session, int hard_timeout, int inactivity_timeout)
{
	if (but_session_isnull(session)) {
		return STATUS_ENOEXIST;
	}
	
/*GET*/	if (but_shm_timeout(session->data, hard_timeout, inactivity_timeout)) {
/*UNLINK*/	but_session_unlink(session);
		return STATUS_ENOEXIST;
	} else {
/*SET*/		session->data->atime = (int)apr_time_sec(apr_time_now());
	}

	return STATUS_OK;
}

/*
 * Get the cookies in the cookie store.
 * session is a valid session.
 * Returns NULL if session is not a session.
 */
const char *
but_session_get_cookies(session_t *session)
{
	if (but_session_isnull(session)) {
		return NULL;
	}
	return collect_cookies_from_cookiestore(session->request, session->data->cookiestore_index);
}

/*
 * Store a cookie in the cookie store of a session.
 * session is a valid session.
 * Returns STATUS_ENOEXIST if session does not exist.
 */
apr_status_t
but_session_set_cookie(session_t *session, const char *key, const char *value, int locid)
{
	if (but_session_isnull(session)) {
		return STATUS_ENOEXIST;
	}
	return store_cookie_into_session(session->request, session->data, key, value, locid);
}

/*
 * Renew the session.  Replaces the session contained in the session_t with a new session,
 * copies over session content from the old to the new session, and deletes the old one.
 * No cookies are created or updated.
 * session is a valid session.
 * Returns STATUS_ENOEXIST if session does not exist.
 */
apr_status_t
but_session_renew(session_t *session)
{
	apr_status_t status;
	session_data_t *old_data;

	if (but_session_isnull(session)) {
		return STATUS_ENOEXIST;
	}

	old_data = session->data;

	status = but_session_create(session);
	if (status != STATUS_OK) {
		return status;
	}

	session->data->ctime                 = old_data->ctime;
	session->data->atime                 = old_data->atime;
	session->data->cookiestore_index     = old_data->cookiestore_index;
	session->data->logon_state           = old_data->logon_state;
	session->data->redirect_on_auth_flag = old_data->redirect_on_auth_flag;
	session->data->auth_strength         = old_data->auth_strength;
	apr_cpystrn(session->data->url, old_data->url, sizeof(session->data->url));
	apr_cpystrn(session->data->service_list, old_data->service_list, sizeof(session->data->service_list));
	apr_cpystrn(session->data->redirect_url_after_login, old_data->redirect_url_after_login, sizeof(session->data->redirect_url_after_login));
	old_data->cookiestore_index          = -1; /* moved to new session ctx */

	but_shm_free(old_data);
	return STATUS_OK;
}

