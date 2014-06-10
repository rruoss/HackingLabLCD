/* $Id: mod_but_shm.c 147 2010-05-30 20:28:01Z ibuetler $ */

#include "mod_but.h"

/*
 * This code will fail miserably with a multithreaded MPM.
 * It will also fail occasionally with a multiprocess MPM.
 * XXX Introduce a mutex for SHM synchronization.
 */

static apr_shm_t *cs_shm = NULL;
static apr_shm_t *cs_shm_cookiestore = NULL;
static session_data_t *sessions;
static cookie_t *cookies;

static void
but_shm_clear(session_data_t *session_data)
{
	memset(session_data, 0, sizeof(session_data_t));
}

static void
but_cookie_clear(cookie_t *cookie)
{
	apr_cpystrn(cookie->name, "empty", sizeof(cookie->name));
	apr_cpystrn(cookie->value, "empty", sizeof(cookie->value));
	cookie->next = -1;
	cookie->prev = -1;
	cookie->location_id = -1;
	cookie->slot_used = 0;
}

/*****************************************************************************
 * SHM Core for MOD_BUT Session Handling
 */

apr_status_t
but_shm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t status;
	apr_pool_t *mypool;
	apr_size_t size;

	status = apr_pool_create(&mypool, p);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM) Unable to create client pool for SHM");
		return status;
	}

	size = (apr_size_t)MOD_BUT_SESSION_COUNT * sizeof(session_data_t);
	ERRLOG_SRV_INFO("(SHM) Size of the shared memory allocation: %d kBytes", size/1024);

	status = apr_shm_create(&cs_shm, size, tmpnam(NULL), p);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM) Failed to create shared memory");
		return status;
	} else {
		ERRLOG_SRV_INFO("(SHM) Successfully created shared memory");
	}

	sessions = (session_data_t*)apr_shm_baseaddr_get(cs_shm);
	memset(sessions, 0, size);

	ERRLOG_SRV_INFO("(SHM) Execution of mod_but_shm_initialize was successful");
	apr_pool_cleanup_register(mypool, NULL, shm_cleanup, apr_pool_cleanup_null);
	return OK;
}


/**
 * Frees the shared memory
 * @param not_used Unused parameter (@see apache doc for more information)
 * @return Status (always success, yeah =) )
 */
apr_status_t
shm_cleanup(void *not_used)
{
	apr_status_t status = APR_SUCCESS;
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Cleaning shared memory");

	if (cs_shm) {
		status = apr_shm_destroy(cs_shm);
		if (status != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Failed to destroy shared memory");
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Successfully destroyed shared memory");
		}
		cs_shm = NULL;
	}
	return status;
}

session_data_t *
get_session_by_index(int index)
{
	return &(sessions[index]);
}

/*
 * Search through the session store, looking for an empty session slot.
 * If a session is found which has reached it's timeout, that slot will
 * be free'd and reused for the new session.
 *
 * Note that it is important to save the unparsed URI here, so that URL encoding is preserved.
 * If we used the parsed URI here, we'd open up ourselves to a HTTP Response Splitting attack
 * through CR/LF injection.
 *
 * Writes SHM offset of newly generated session to shmoffset.
 *
 * Only called from session handling code.
 *
 * Returns:
 *	STATUS_OK	and SHM offset in shmoffset
 *	STATUS_ESHMFULL	if out of SHM space
 *	STATUS_ERROR	for all other internal errors
 */
apr_status_t
create_new_shm_session(request_rec *r, const char *sid, int *shmoffset)
{
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	int i;
	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
		session_data_t *session_data = get_session_by_index(i);

		/* free this slot if it has reached it's timeout */
		if (session_data->slot_used) {
			if (but_shm_timeout(session_data, config->session_hard_timeout, config->session_inactivity_timeout)) {
				but_shm_free(session_data);
			}
		}

		/* slot was free all along or has reached it's timeout */
		if (!session_data->slot_used) {
			ERRLOG_INFO("Setting-up new SHM session at offset [%d]", i);
			apr_cpystrn(session_data->session_name, config->cookie_name, sizeof(session_data->session_name));
			apr_cpystrn(session_data->session_id, sid, sizeof(session_data->session_id));
			/* Store r->unparsed_uri to prevent HTTP Response Splitting attacks;
			 * strip __cookie_try in case the user has a bookmark containing
			 * a __cookie_try argument - otherwise we get a redirection loop */
			apr_cpystrn(session_data->url, mod_but_strip_cookie_try(r->unparsed_uri), sizeof(session_data->url));
			apr_cpystrn(session_data->service_list, config->service_list_cookie_value, sizeof(session_data->service_list));
			session_data->ctime = (int)apr_time_sec(apr_time_now());
			session_data->atime = session_data->ctime;
			session_data->cookiestore_index = -1;
			session_data->redirect_on_auth_flag = 1;
			session_data->logon_state = 0;
			session_data->auth_strength = 0;
			session_data->slot_used = 1;
			ERRLOG_INFO("Session name [%s] value [%s] ctime [%ds]", session_data->session_name, session_data->session_id, session_data->ctime);

			*shmoffset = i;
			return STATUS_OK;
		}
	}

	return STATUS_ESHMFULL;
}

void
but_shm_free(session_data_t *session_data)
{
	if (session_data->cookiestore_index != -1) {
		but_cookiestore_free(session_data->cookiestore_index);
	}
	but_shm_clear(session_data);
}

/*
 * Check whether the session has reached a timeout.
 * Returns zero if session is still valid, non-zero if timeout reached.
 * Does not modify the session in any way.
 */
int
but_shm_timeout(session_data_t *session_data, int hard_timeout, int inactivity_timeout)
{
	int now = (int)apr_time_sec(apr_time_now()); /* XXX make this a param and get time once per request */

/*GET*/	return ((now - session_data->ctime) > hard_timeout ||
	        (now - session_data->atime) > inactivity_timeout);
}


/*****************************************************************************
 * Cookie Store Functionality
 */
apr_status_t
but_shm_initialize_cookiestore(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t status;
	apr_pool_t *mypool;
	apr_size_t size;
	int i;

	status = apr_pool_create(&mypool, p);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Unable to create client pool for SHM cookiestore");
		return status;
	}

	size = (apr_size_t)MOD_BUT_COOKIESTORE_COUNT * sizeof(cookie_t);
	ERRLOG_SRV_INFO("(SHM COOKIESTORE) Size of the shared cookiestore memory allocation: %d kBytes", size/1024);

	status = apr_shm_create(&cs_shm_cookiestore, size, tmpnam(NULL), p);
	if (status != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Failed to create shared cookiestore memory");
		return status;
	} else {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Successfully created shared cookiestore memory");
	}

	cookies = (cookie_t*)apr_shm_baseaddr_get(cs_shm_cookiestore);
	for (i = 0; i < MOD_BUT_COOKIESTORE_COUNT; i++) {
		but_cookie_clear(&(cookies[i]));
	}

	apr_pool_cleanup_register(mypool, NULL, shm_cleanup_cookiestore, apr_pool_cleanup_null);
	return OK;
}

apr_status_t
shm_cleanup_cookiestore(void *not_used)
{
	apr_status_t status = APR_SUCCESS;
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Cleaning shared cookiestore memory and RMM by shm_cleanup_cookiestore");

	if (cs_shm_cookiestore) {
		status = apr_shm_destroy(cs_shm_cookiestore);
		if (status != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Failed to destroy shared cookiestore memory");
			return status;
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Successfully destroyed shared cookiestore memory");
		}
		cs_shm_cookiestore = NULL;
	}
	return status;
}

/*
 * Find cookie object by SHM index.
 */
static cookie_t *
get_cookie_by_index(int index)
{
	return index == -1 ? NULL : &(cookies[index]);
}

/*
 * Find cookie index by name.
 */
static int
get_cookie_index_by_name(request_rec *r, int index, const char *key, int locid)
{
	cookie_t *c;

	for (c = get_cookie_by_index(index);
	     c && !(!apr_strnatcmp(key, c->name) && (locid == c->location_id));
	     c = get_cookie_by_index(index)) {
		index = c->next;
	}
	return index;
}

/*
 * Returns cookie store slot or -1 if no more slots are available.
 */
static int
find_empty_cookiestore_slot() {
	int i;

	for (i = 0; i < MOD_BUT_COOKIESTORE_COUNT; i++) {
		cookie_t *c = get_cookie_by_index(i);
		if (!c->slot_used) {
			c->slot_used = 1;
			return i;
		}
	}

	return -1;
}

/*
 * Store a cookie into the session cookie store.
 */
apr_status_t
store_cookie_into_session(request_rec *r, session_data_t *session_data, const char *key, const char *value, int locid)
{
	cookie_t *cookie;
	int index;

	index = get_cookie_index_by_name(r, session_data->cookiestore_index, key, locid);

	/* delete on special cookie value "deleted" */
	if (!apr_strnatcmp(value, "deleted")) {
		if (index != -1) {
			cookie = get_cookie_by_index(index);
			/* FIXME simplify this unlink code */
			if (cookie->prev == -1 && cookie->next == -1) {
				session_data->cookiestore_index = -1;
			} else if (cookie->prev == -1 && cookie->next >= 0) {
				session_data->cookiestore_index = cookie->next;
				get_cookie_by_index(cookie->next)->prev = -1;
			} else if (cookie->prev >= 0 && cookie->next == -1) {
				get_cookie_by_index(cookie->prev)->next = -1;
			} else if (cookie->prev >= 0 && cookie->next >= 0) {
				get_cookie_by_index(cookie->prev)->next = cookie->next;
				get_cookie_by_index(cookie->next)->prev = cookie->prev;
			}
			but_cookie_clear(cookie);
		}
		return STATUS_OK;
	}

	/* update existing cookie */
	if (index != -1) {
		cookie = get_cookie_by_index(index);
		apr_cpystrn(cookie->value, value, sizeof(cookie->value));
		return STATUS_OK;
	}

	/* add new cookie */
	index = find_empty_cookiestore_slot();
	if (index == -1) {
		ERRLOG_CRIT("Unable to find an empty cookie store slot!");
		return STATUS_ESHMFULL;
	}

	cookie = get_cookie_by_index(index);
	/* cookie->slot_used was set to 1 by find_empty_cookiestore_slot() */
	apr_cpystrn(cookie->name, key, sizeof(cookie->name));
	apr_cpystrn(cookie->value, value, sizeof(cookie->value));
	cookie->location_id = locid;
	if (session_data->cookiestore_index == -1) {
		cookie->prev = -1;
		cookie->next = -1;
		session_data->cookiestore_index = index;
	} else {
		get_cookie_by_index(session_data->cookiestore_index)->prev = index;
		cookie->next = session_data->cookiestore_index;
		session_data->cookiestore_index = index;
	}
	return STATUS_OK;
}

void
but_cookiestore_free(int anchor)
{
	cookie_t *c = get_cookie_by_index(anchor);

	if (c->next == -1) {
		but_cookie_clear(c);
	} else {
		int next_index = c->next;
		but_cookie_clear(c);
		but_cookiestore_free(next_index);
	}
}


/*
 * Build a string containing all cookies in the cookie store at anchor.
 * String is allocated from r->pool.
 */
const char *
collect_cookies_from_cookiestore(request_rec *r, int anchor)
{
	mod_but_dir_t *dconfig;
	cookie_t *c;
	const char *cookiestr = NULL;

	dconfig = ap_get_module_config(r->per_dir_config, &but_module);
	if (!dconfig) {
		ERRLOG_CRIT("Illegal directory config, no cookies added");
		return NULL;
	}

	for (c = get_cookie_by_index(anchor);;
	     c = get_cookie_by_index(c->next)) {
		if (c->location_id == dconfig->mod_but_location_id) {
			if (!cookiestr) {
				cookiestr = apr_psprintf(r->pool, "%s=%s", c->name, c->value);
			} else {
				cookiestr = apr_psprintf(r->pool, "%s; %s=%s", cookiestr, c->name, c->value);
			}

			if (!cookiestr) {
				ERRLOG_CRIT("Out of memory!");
				return NULL;
			}
		}
		if (c->next == -1)
			break;
	}
	return cookiestr;
}



