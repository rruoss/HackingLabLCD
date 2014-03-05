/*#############################################
#
# Title:        mod_but_shm.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
/* $Id: mod_but_shm.c 65 2008-05-30 17:05:05Z droethli $ */

#include "mod_but.h"

/*
 * This code will fail miserably with a multithreaded MPM.
 * XXX Rewrite the SHM code to be thread-safe and properly synchronized.
 */

static apr_shm_t *cs_shm = NULL;
static apr_rmm_t *cs_rmm = NULL;
static apr_rmm_off_t *off = NULL;

static apr_shm_t *cs_shm_history = NULL;
static apr_rmm_t *cs_rmm_history = NULL;
static apr_rmm_off_t *off_history = NULL;

static apr_shm_t *cs_shm_cookiestore = NULL;
static apr_rmm_t *cs_rmm_cookiestore = NULL;
static apr_rmm_off_t *off_cookiestore = NULL;

/*****************************************************************************
 * SHM Core for MOD_BUT Session Handling
 */

apr_status_t
mod_but_shm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t rv;
	apr_pool_t *mypool;
	apr_status_t sts;
	apr_size_t size;
	int i;

	rv = apr_pool_create(&mypool, p);
	if (rv != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM) Unable to create client pool for SHM");
		return rv;
	}

	size = (apr_size_t)MOD_BUT_SESSION_COUNT * sizeof(mod_but_cookie) + apr_rmm_overhead_get(MOD_BUT_SESSION_COUNT + 1);
	ERRLOG_SRV_INFO("(SHM) Size of the shared memory allocation: %d kBytes", size/1024);

	sts = apr_shm_create(&cs_shm, size, tmpnam(NULL), p);
	if (sts != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM) Failed to create shared memory");
		return sts;
	} else {
		ERRLOG_SRV_INFO("(SHM) Successfully created shared memory");
	}

	sts = apr_rmm_init(&cs_rmm, NULL, apr_shm_baseaddr_get(cs_shm), size, p);
	if (sts != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM) Failed to initialize the RMM segment");
		return sts;
	} else {
		ERRLOG_SRV_INFO("(SHM) Initialized RMM successfully");
	}

	ERRLOG_SRV_INFO("(SHM) STARTING to malloc offsets in RMM");
	off = apr_palloc(p, MOD_BUT_SESSION_COUNT * sizeof(apr_rmm_off_t));
	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
		//ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: Malloc cs_rmm %d", i);
		off[i] = apr_rmm_malloc(cs_rmm, sizeof(mod_but_cookie));
	}

	/*
	 * Init of RMM with default values
	 */
	ERRLOG_SRV_INFO("(SHM) STARTING to give every session the default values");
	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
		mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[i]);
		apr_cpystrn(c->session_name, "empty", sizeof(c->session_name));
		apr_cpystrn(c->session_value, "empty", sizeof(c->session_value));
		apr_cpystrn(c->service_list, "empty", sizeof(c->service_list));
		c->link_to_cookiestore = -1;
		c->logon_state = 0;
		c->logon_flag = 0;	// used for redirect to ORIG_URL after successful authentication
		c->auth_strength = 0;
	}
	ERRLOG_SRV_INFO("(SHM) END to give every session the default values");
	ERRLOG_SRV_INFO("(SHM) Execution of mod_but_shm_initialize was successfully");
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
	apr_status_t rv = 0;
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Cleaning shared memory and RMM by shm_cleanup");

	if(cs_rmm) {
		rv = apr_rmm_destroy(cs_rmm);
		if (rv != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Failed to destroy RMM");
			return rv;
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Successfully destroyed RMM");
			cs_rmm = NULL;
		}
	}

	if (cs_shm) {
		rv = apr_shm_destroy(cs_shm);
		if (rv != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Failed to destroy shared memory");
			return rv;
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Successfully destroyed shared memory");
			cs_rmm = NULL;
		}
	}
	return rv;
}


apr_shm_t *
find_cs_shm()
{
	return cs_shm;
}

apr_rmm_t *
find_cs_rmm()
{
	return cs_rmm;
}

apr_rmm_off_t *
find_cs_rmm_off()
{
	return off;
}



/*****************************************************************************
 * Session History
 */
apr_status_t
mod_but_shm_initialize_history(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t rv;
	apr_pool_t *mypool;
	apr_status_t sts;
	apr_size_t size;
	int i;

	rv = apr_pool_create(&mypool, p);
	if (rv != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM HISTORY) Unable to create client pool for SHM history");
		return rv;
	}

	size = (apr_size_t)MOD_BUT_SESSION_HISTORY_COUNT * sizeof(mod_but_cookie_history) + apr_rmm_overhead_get(MOD_BUT_SESSION_HISTORY_COUNT + 1);
	ERRLOG_SRV_INFO("(SHM HISTORY) Size of the shared history memory allocation: %d kBytes", size/1024);

	sts = apr_shm_create(&cs_shm_history, size, tmpnam(NULL), p);
	if (sts != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM HISTORY) Failed to create shared history memory");
		return sts;
	} else {
		ERRLOG_SRV_INFO("(SHM HISTORY) Successfully created shared history memory");
	}

	sts = apr_rmm_init(&cs_rmm_history,NULL,apr_shm_baseaddr_get(cs_shm_history),size,p);
	if (sts != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM HISTORY) Failed to initialize the RMM segment");
		return sts;
	} else {
		ERRLOG_SRV_INFO("(SHM HISTORY) Initialized RMM successfully");
	}

	ERRLOG_SRV_INFO("(SHM HISTORY) STARTING to malloc offsets in RMM");
	off_history = apr_palloc(p, MOD_BUT_SESSION_HISTORY_COUNT * sizeof(apr_rmm_off_t));
	for (i = 0; i < MOD_BUT_SESSION_HISTORY_COUNT; i++) {
		//ERRLOG_SRV_INFO("Malloc cs_rmm_history %d", i);
		off_history[i] = apr_rmm_malloc(cs_rmm_history, sizeof(mod_but_cookie_history));
	}

	/*
	 * Init of RMM with default values
	 */
	ERRLOG_SRV_INFO("(SHM HISTORY) STARTING to give every session the default values");
	for (i = 0; i < MOD_BUT_SESSION_HISTORY_COUNT; i++) {
		mod_but_cookie_history *c = apr_rmm_addr_get(cs_rmm_history, off_history[i]);
		apr_cpystrn(c->session_value, "empty", sizeof(c->session_value));
	}
	ERRLOG_SRV_INFO("(SHM HISTORY) END to give every session the default values");
	ERRLOG_SRV_INFO("(SHM HISTORY) Execution of mod_but_shm_initialize_history was successfully");
	apr_pool_cleanup_register(mypool, NULL, shm_cleanup_history, apr_pool_cleanup_null);
	return OK;
}

apr_status_t
shm_cleanup_history(void *not_used)
{
	apr_status_t rv = 0;
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Cleaning shared history memory and RMM by shm_cleanup_history");

	if(cs_rmm_history) {
		rv = apr_rmm_destroy(cs_rmm_history);
		if (rv != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Failed to destroy RMM history");
			return rv;
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Successfully destroyed RMM history");
			cs_rmm_history = NULL;
		}
	}

	if (cs_shm_history) {
		rv = apr_shm_destroy(cs_shm_history);
		if (rv != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Failed to destroy shared history memory");
			return rv;
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Successfully destroyed shared history memory");
			cs_rmm_history = NULL;
		}
	}
	return rv;
}

/*
 * Create the required structures in the shared memory segment.
 * The following stuff goes to the shared memory:
 *   a) Cookie Name
 *   b) Cookie Value
 *   c) First URL (which is later used for redirection)
 *
 * Note that it is important to save the unparsed URI here, so that URL encoding is preserved.
 * If we used the parsed URI here, we'd open up ourselves to a HTTP Response Splitting attack
 * through CR/LF injection.
 *
 * Function "searches" for free space within the shm section, and creates a new shm structure,
 * containing all relevant information a mod_but session requires.
 *
 * Writes SHM offset of newly generated session to shmoffset.
 *
 * Returns:
 *	STATUS_OK	and SHM offset in shmoffset
 *	STATUS_ESHM	if out of SHM space
 *	STATUS_EHACKING	if hacking is detected
 *	STATUS_ERROR	for all other internal errors
 */
apr_status_t
create_new_shm_session(request_rec *r, char *sid, int *shmoffset)
{
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	int i;
	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
		mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[i]);
		ERRLOG_INFO("Existing session name [%s] and value [%s]", c->session_name, c->session_value);

		if (!apr_strnatcmp(c->session_name, "empty")) {
			ERRLOG_INFO("Setting-up new SHM session at offset [%d]", i);
			apr_cpystrn(c->session_name, config->cookie_name, sizeof(c->session_name));
			apr_cpystrn(c->session_value, sid, sizeof(c->session_value));
			/* Store r->unparsed_uri to prevent HTTP Response Splitting attacks */
			apr_cpystrn(c->session_firsturl, r->unparsed_uri, sizeof(c->session_firsturl));
			c->session_create_time = (int)apr_time_sec(apr_time_now());
			c->session_last_access_time = c->session_create_time;
			c->link_to_cookiestore=-1;
			c->logon_state = 0;
			c->auth_strength = 0;
			apr_cpystrn(c->service_list, config->service_list_cookie_value, sizeof(c->service_list));

			ERRLOG_CRIT("Session original URL is [%s]", c->session_firsturl);
			ERRLOG_INFO("Session name [%s] value [%s] ctime [%ds]", c->session_name, c->session_value, c->session_create_time);

			*shmoffset = i;
			return STATUS_OK;
		}
	}

	ERRLOG_INFO("No empty session slot found; all SHM used up");
	return STATUS_ESHM;
}

void
cleaning_shm_from_expired_session(request_rec *r)
{
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	int y;
	for (y = 0; y < MOD_BUT_SESSION_COUNT; y++) {
		mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[y]);

		apr_time_t curtime = apr_time_now();
		int tnow = (int)apr_time_sec(curtime);
		int tcreate = c->session_create_time;
		int tlastaccess = c->session_last_access_time;

		if (!apr_strnatcmp(c->session_name, config->cookie_name)) {
			if ((tnow - tcreate) > config->session_timeout) {
				ERRLOG_INFO("(SHM) Cleanup Task A: Delta between tnow and tcreate %d at shmoffset %d", tnow-tcreate, y);
				mod_but_delete_session(y, r);
			} else {
				if ((tnow - tlastaccess) > config->session_inactivity_timeout) {
					ERRLOG_INFO("(SHM) Cleanup Task B: Delta between tnow and tlastaccess %d at shmoffset %d", tnow-tlastaccess, y);
					mod_but_delete_session(y, r);
				}
			}
		}
	}
}


void
cleaning_shm_history_from_expired_session(request_rec *r)
{
	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
	apr_time_t curtime = apr_time_now();
	apr_time_t tnow = apr_time_sec(curtime);

	int y;
	for (y = 0; y < MOD_BUT_SESSION_HISTORY_COUNT; y++) {
		mod_but_cookie_history *c_history = apr_rmm_addr_get(cs_rmm_history, off_history[y]);
		apr_time_t tdelete = c_history->session_delete_time;
		if (apr_strnatcmp(c_history->session_value, "empty")) {
			if ((tnow - tdelete) > config->session_timeout_history) {
				//ERRLOG_INFO("(SHM HISTORY) Cleaning: Delta between tnow and tdelete %d and session value %s", tnow-tdelete, c_history->session_value);
				apr_cpystrn(c_history->session_value, "empty", sizeof(c_history->session_value));
				c_history->session_delete_time = 0;
			}
		}
	}
}

apr_rmm_t *
find_cs_rmm_history()
{
	return cs_rmm_history;
}

apr_rmm_off_t *
find_cs_rmm_off_history()
{
	return off_history;
}



/*****************************************************************************
 * Cookie Store Functionality
 */
apr_status_t
mod_but_shm_initialize_cookiestore(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	apr_status_t rv;
	apr_pool_t *mypool;
	apr_status_t sts;
	apr_size_t size;
	int i;

	rv = apr_pool_create(&mypool, p);
	if (rv != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Unable to create client pool for SHM cookiestore");
		return rv;
	}

	size = (apr_size_t)MOD_BUT_COOKIESTORE_COUNT * sizeof(mod_but_cookie_cookiestore) + apr_rmm_overhead_get(MOD_BUT_COOKIESTORE_COUNT + 1);
	ERRLOG_SRV_INFO("(SHM COOKIESTORE) Size of the shared cookiestore memory allocation: %d kBytes", size/1024);

	sts = apr_shm_create(&cs_shm_cookiestore, size, tmpnam(NULL), p);
	if (sts != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Failed to create shared cookiestore memory");
		return sts;
	} else {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Successfully created shared cookiestore memory");
	}

	sts = apr_rmm_init(&cs_rmm_cookiestore, NULL, apr_shm_baseaddr_get(cs_shm_cookiestore), size, p);
	if (sts != APR_SUCCESS) {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Failed to initialize the RMM segment");
		return sts;
	} else {
		ERRLOG_SRV_INFO("(SHM COOKIESTORE) Initialized RMM successfully");
	}

	ERRLOG_SRV_INFO("(SHM COOKIESTORE) STARTING to malloc offsets in RMM");
	off_cookiestore = apr_palloc(p, MOD_BUT_COOKIESTORE_COUNT * sizeof(apr_rmm_off_t));
	for (i = 0; i < MOD_BUT_COOKIESTORE_COUNT; i++) {
		//ERRLOG_SRV_INFO("Malloc cs_rmm_cookiestore %d", i);
		off_cookiestore[i] = apr_rmm_malloc(cs_rmm_cookiestore, sizeof(mod_but_cookie_cookiestore));
	}

	/*
	 * Init of RMM with default values
	 */
	ERRLOG_SRV_INFO("(SHM COOKIESTORE) STARTING to give every session the default values");
	for (i = 0; i < MOD_BUT_COOKIESTORE_COUNT; i++) {
		mod_but_cookie_cookiestore *c = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[i]);
		apr_cpystrn(c->cookie_name, "empty", sizeof(c->cookie_name));
		apr_cpystrn(c->cookie_value, "empty", sizeof(c->cookie_value));
		c->cookie_next = -1;
		c->cookie_before = -1;
		c->cookie_slot_used = -1;
		c->location_id = -1;
	}
	ERRLOG_SRV_INFO("(SHM COOKIESTORE) END to give every session the default values");
	ERRLOG_SRV_INFO("(SHM COOKIESTORE) Execution of mod_but_shm_initialize_cookiestore was successfully");
	apr_pool_cleanup_register(mypool, NULL, shm_cleanup_cookiestore, apr_pool_cleanup_null);
	return OK;
}

apr_status_t
shm_cleanup_cookiestore(void *not_used)
{
	apr_status_t rv = 0;
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Cleaning shared cookiestore memory and RMM by shm_cleanup_cookiestore");

	if(cs_rmm_cookiestore) {
		rv = apr_rmm_destroy(cs_rmm_cookiestore);
		if (rv != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Failed to destroy RMM cookiestore");
			return rv;
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Successfully destroyed RMM cookiestore");
			cs_rmm_cookiestore = NULL;
		}
	}

	if (cs_shm_cookiestore) {
		rv = apr_shm_destroy(cs_shm_cookiestore);
		if (rv != APR_SUCCESS) {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Failed to destroy shared cookiestore memory");
			return rv;
		} else {
			ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Successfully destroyed shared cookiestore memory");
			cs_rmm_cookiestore = NULL;
		}
	}
	return rv;
}

apr_rmm_t *
find_cs_rmm_cookiestore()
{
	return cs_rmm_cookiestore;
}

apr_rmm_off_t *
find_cs_rmm_off_cookiestore()
{
	return off_cookiestore;
}

