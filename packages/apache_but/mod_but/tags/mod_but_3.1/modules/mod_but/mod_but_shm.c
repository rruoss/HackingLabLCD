/*#############################################
#
# Title:        mod_but_shm.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/

#include "mod_but.h"


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

	SHM Core for MOD_BUT Session Handling

*/

apr_status_t mod_but_shm_initialize(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    apr_pool_t *mypool;
    apr_status_t sts;
    apr_size_t size;
    int i;

    rv = apr_pool_create(&mypool, p);
    if (rv != APR_SUCCESS) {
    	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Unable to create client pool for SHM");
        return rv;
    }



  	size = (apr_size_t)MOD_BUT_SESSION_COUNT * sizeof(mod_but_cookie) + apr_rmm_overhead_get(MOD_BUT_SESSION_COUNT + 1);
        ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) Size of the shared memory allocation: %d kBytes", size/1000 );

        sts = apr_shm_create(&cs_shm, size, tmpnam(NULL), p);
        if (sts != APR_SUCCESS) {
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) Failed to create shared memory" );
                return sts;
        }else{
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) Successfully created shared memory" );
        }


        sts = apr_rmm_init(&cs_rmm,NULL,apr_shm_baseaddr_get(cs_shm),size,p);
        if (sts != APR_SUCCESS) {
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) Failed to initialize the RMM segment" );
                return sts;
        }else{
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) Initialized RMM successfully" );
        }


	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) STARTING to malloc offsets in RMM");
	off = apr_palloc(p, MOD_BUT_SESSION_COUNT * sizeof(apr_rmm_off_t));
	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
		//ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: Malloc cs_rmm %d", i);
		off[i] = apr_rmm_malloc(cs_rmm, sizeof(mod_but_cookie));
	}


/*
	Init of RMM with default values

*/
	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) STARTING to give every session the default values");
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
	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM) END to give every session the default values");
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Execution of mod_but_shm_initialize was successfully");
	apr_pool_cleanup_register(mypool, NULL, shm_cleanup, apr_pool_cleanup_null);
	return OK;
}


/**
 * Frees the shared memory
 * @param not_used Unused parameter (@see apache doc for more information)
 * @return Status (always success, yeah =) )
 */
apr_status_t shm_cleanup(void *not_used)
{
    apr_status_t rv = 0;
    ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Cleaning shared memory and RMM by shm_cleanup");

    if(cs_rmm) {
        rv = apr_rmm_destroy(cs_rmm);
	if (rv != APR_SUCCESS) {
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Failed to destroy RMM");
        	return rv;
	}else{
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Successfully destroyed RMM");
        	cs_rmm = NULL;
	}
    }

    if (cs_shm) {
        rv = apr_shm_destroy(cs_shm);
	if (rv != APR_SUCCESS) {
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Failed to destroy shared memory");
        	return rv;
	}else{
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM) Successfully destroyed shared memory");
        	cs_rmm = NULL;
	}
    }
    return rv;
}


apr_shm_t *find_cs_shm()
{
	return cs_shm;
}

apr_rmm_t *find_cs_rmm()
{
	return cs_rmm;
}

apr_rmm_off_t *find_cs_rmm_off()
{
	return off;
}



/*****************************************************************************

	Session History

*/
apr_status_t mod_but_shm_initialize_history(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    apr_pool_t *mypool;
    apr_status_t sts;
    apr_size_t size;
    int i;

    rv = apr_pool_create(&mypool, p);
    if (rv != APR_SUCCESS) {
    	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Unable to create client pool for SHM history");
        return rv;
    }



  	size = (apr_size_t)MOD_BUT_SESSION_HISTORY_COUNT * sizeof(mod_but_cookie_history) + apr_rmm_overhead_get(MOD_BUT_SESSION_HISTORY_COUNT + 1);
        ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) Size of the shared history memory allocation: %d kBytes", size/1000 );

        sts = apr_shm_create(&cs_shm_history, size, tmpnam(NULL), p);
        if (sts != APR_SUCCESS) {
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) Failed to create shared history memory" );
                return sts;
        }else{
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) Successfully created shared history memory" );
        }


        sts = apr_rmm_init(&cs_rmm_history,NULL,apr_shm_baseaddr_get(cs_shm_history),size,p);
        if (sts != APR_SUCCESS) {
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) Failed to initialize the RMM segment" );
                return sts;
        }else{
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) Initialized RMM successfully" );
        }


	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) STARTING to malloc offsets in RMM");
	off_history = apr_palloc(p, MOD_BUT_SESSION_HISTORY_COUNT * sizeof(apr_rmm_off_t));
	for (i = 0; i < MOD_BUT_SESSION_HISTORY_COUNT; i++) {
		//ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: Malloc cs_rmm_history %d", i);
		off_history[i] = apr_rmm_malloc(cs_rmm_history, sizeof(mod_but_cookie_history));
	}


/*
	Init of RMM with default values

*/
	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) STARTING to give every session the default values");
        for (i = 0; i < MOD_BUT_SESSION_HISTORY_COUNT; i++) {
        	mod_but_cookie_history *c = apr_rmm_addr_get(cs_rmm_history, off_history[i]);
		apr_cpystrn(c->session_value, "empty", sizeof(c->session_value));
	}
	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM HISTORY) END to give every session the default values");
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Execution of mod_but_shm_initialize_history was successfully");
	apr_pool_cleanup_register(mypool, NULL, shm_cleanup_history, apr_pool_cleanup_null);
	return OK;
}


apr_status_t shm_cleanup_history(void *not_used)
{
    apr_status_t rv = 0;
    ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Cleaning shared history memory and RMM by shm_cleanup_history");

    if(cs_rmm_history) {
        rv = apr_rmm_destroy(cs_rmm_history);
	if (rv != APR_SUCCESS) {
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Failed to destroy RMM history");
        	return rv;
	}else{
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Successfully destroyed RMM history");
        	cs_rmm_history = NULL;
	}
    }

    if (cs_shm_history) {
        rv = apr_shm_destroy(cs_shm_history);
	if (rv != APR_SUCCESS) {
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Failed to destroy shared history memory");
        	return rv;
	}else{
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM HISTORY) Successfully destroyed shared history memory");
        	cs_rmm_history = NULL;
	}
    }
    return rv;
}


/*
	create_new_shm_session will create the required structures in the shared memory segment. The following
	stuff goes to the shared memory

	a) Cookie Name
	b) Cookie Value
	c) First URL (which is later used for redirection)

	Function "searches" for free space within the shm section, and creates a new shm structure, containing
	all relevant information a mod_but_session requires.

	The return value is the shm offset.

*/

int create_new_shm_session(request_rec *r, unsigned char *sid)
{
       pcre *re = NULL;  					// the regular expression
       const char *error;				// error text for the failed regex compilation
       int error_offset;				// offset of the regex compilation error, if any
       int rc = 0;					// return code of pcre_exec
       int re_vector[3072];

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	int i;

    re = pcre_compile("\r\n", 0, &error, &error_offset, NULL);

    if (re == NULL) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: return code of pcre_compile is NULL");
    }

    rc = pcre_exec(re, NULL, r->uri, strlen(r->uri), 0, 0, re_vector, 3072);

    if (rc < 0) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: r->uri does not contain CR/LF [%s]", r->uri);
    }

    if (rc < 0 && rc != PCRE_ERROR_NOMATCH) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: r->uri does not contain CR/LF [%s]", r->uri);
    }

    if (rc == 0) {
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: PCRE output vector too small (%d)", 3072/3-1);
        ap_log_rerror(PC_LOG_INFO, r, "mod_but: Problems with pcre CRLF = %s", r->uri);
	return DECLINED;
    }

	for (i = 0; i < MOD_BUT_SESSION_COUNT; i++) {
        	mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[i]);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: EXISTING SESSION_NAME [%s] und SESSION_VALUE [%s]", c->session_name, c->session_value);

		if (!apr_strnatcmp(c->session_name, "empty"))
		{
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: Setting-up new SHM Session");
			apr_cpystrn(c->session_name, config->cookie_name, sizeof(c->session_name));
			apr_cpystrn(c->session_value, (char *)sid, sizeof(c->session_value));
			if (rc > 0) {
        			ap_log_rerror(PC_LOG_INFO, r, "mod_but: ATTACK!!!! r->uri contains CR/LF [%s]", r->uri);
				apr_cpystrn(c->session_firsturl, "ATTACK", sizeof(c->session_firsturl));
    			} else {
				apr_cpystrn(c->session_firsturl, r->uri, sizeof(c->session_firsturl));
			}
	
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but_shm.c: SHM: Save OrigURL (session_firsturl) [%s]", c->session_firsturl);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: SESSION_NAME [%s] und SESSION_VALUE [%s] and OFFSET [%d]", c->session_name, c->session_value, i);
			ap_log_rerror(PC_LOG_CRIT, r, "mod_but_shm.c: SESSION_FIRSTURL [%s]", c->session_firsturl);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: SESSION_OFFSET [%d]", i);

			c->session_create_time = (int)apr_time_sec(apr_time_now());
			c->session_last_access_time = c->session_create_time;
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: CREATE TIME (in seconds) [%d] at shmoffset %d", c->session_create_time, i);
			c->link_to_cookiestore=-1;
			c->logon_state = 0;
			c->auth_strength = 0;
			apr_cpystrn(c->service_list, config->service_list_cookie_value, sizeof(c->service_list));
			return i;
        	}
	}

	ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: Unable to set new sessions in SHM, because all are used");
	// IVAN (see below)
	return 1000;

}

void cleaning_shm_from_expired_session(request_rec *r){

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);

	int y;
	for (y = 0; y < MOD_BUT_SESSION_COUNT; y++) {
		mod_but_cookie *c = apr_rmm_addr_get(cs_rmm, off[y]);

		apr_time_t curtime = apr_time_now();
		int tnow = (int)apr_time_sec(curtime);
		int tcreate = c->session_create_time;
		int tlastaccess = c->session_last_access_time;

		if (!apr_strnatcmp(c->session_name, config->cookie_name))
		{
			if ((tnow - tcreate) > config->session_timeout){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: (SHM) Cleanup Task A: Delta between tnow and tcreate %d at shmoffset %d", tnow-tcreate, y);
				delete_mod_but_session(y, r);
			}else{
				if ( (tnow - tlastaccess) > config->session_inactivity_timeout){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: (SHM) Cleanup Task B: Delta between tnow and tlastaccess %d at shmoffset %d", tnow-tlastaccess, y);
					delete_mod_but_session(y, r);
				}
			}
        	}
	}
}


void cleaning_shm_history_from_expired_session(request_rec *r){

	mod_but_server_t *config = ap_get_module_config(r->server->module_config, &but_module);
	apr_time_t curtime = apr_time_now();
	apr_time_t tnow = apr_time_sec(curtime);

	int y;
	for (y = 0; y < MOD_BUT_SESSION_HISTORY_COUNT; y++) {

		mod_but_cookie_history *c_history = apr_rmm_addr_get(cs_rmm_history, off_history[y]);

		apr_time_t tdelete = c_history->session_delete_time;

		if (apr_strnatcmp(c_history->session_value, "empty"))
		{
			if ((tnow - tdelete) > config->session_timeout_history){
				//ap_log_rerror(PC_LOG_INFO, r, "mod_but_shm.c: (SHM HISTORY) Cleaning: Delta between tnow and tdelete %d and session value %s", tnow-tdelete, c_history->session_value);
				apr_cpystrn(c_history->session_value, "empty", sizeof(c_history->session_value));
				c_history->session_delete_time = 0;
			}
		}
	}
}



apr_rmm_t *find_cs_rmm_history()
{
	return cs_rmm_history;
}

apr_rmm_off_t *find_cs_rmm_off_history()
{
	return off_history;
}



/*****************************************************************************

	Cookie Store Functionality

*/

apr_status_t mod_but_shm_initialize_cookiestore(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    apr_status_t rv;
    apr_pool_t *mypool;
    apr_status_t sts;
    apr_size_t size;
    int i;

    rv = apr_pool_create(&mypool, p);
    if (rv != APR_SUCCESS) {
    	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Unable to create client pool for SHM cookiestore");
        return rv;
    }



  	size = (apr_size_t)MOD_BUT_COOKIESTORE_COUNT * sizeof(mod_but_cookie_cookiestore) + apr_rmm_overhead_get(MOD_BUT_COOKIESTORE_COUNT + 1);
        ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) Size of the shared cookiestore memory allocation: %d kBytes", size/1000 );

        sts = apr_shm_create(&cs_shm_cookiestore, size, tmpnam(NULL), p);
        if (sts != APR_SUCCESS) {
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) Failed to create shared cookiestore memory" );
                return sts;
        }else{
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) Successfully created shared cookiestore memory" );
        }


        sts = apr_rmm_init(&cs_rmm_cookiestore,NULL,apr_shm_baseaddr_get(cs_shm_cookiestore),size,p);
        if (sts != APR_SUCCESS) {
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) Failed to initialize the RMM segment" );
                return sts;
        }else{
                ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) Initialized RMM successfully" );
        }


	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) STARTING to malloc offsets in RMM");
	off_cookiestore = apr_palloc(p, MOD_BUT_COOKIESTORE_COUNT * sizeof(apr_rmm_off_t));
	for (i = 0; i < MOD_BUT_COOKIESTORE_COUNT; i++) {
		//ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: Malloc cs_rmm_cookiestore %d", i);
		off_cookiestore[i] = apr_rmm_malloc(cs_rmm_cookiestore, sizeof(mod_but_cookie_cookiestore));
	}


/*
	Init of RMM with default values

*/
	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) STARTING to give every session the default values");
        for (i = 0; i < MOD_BUT_COOKIESTORE_COUNT; i++) {
        	mod_but_cookie_cookiestore *c = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[i]);
		apr_cpystrn(c->cookie_name, "empty", sizeof(c->cookie_name));
		apr_cpystrn(c->cookie_value, "empty", sizeof(c->cookie_value));
		c->cookie_next = -1;
		c->cookie_before = -1;
		c->cookie_slot_used = -1;
		c->location_id = -1;
	}
	ap_log_error(PC_LOG_INFO, s, "mod_but_shm.c: (SHM COOKIESTORE) END to give every session the default values");
	ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Execution of mod_but_shm_initialize_cookiestore was successfully");
	apr_pool_cleanup_register(mypool, NULL, shm_cleanup_cookiestore, apr_pool_cleanup_null);
	return OK;
}



apr_status_t shm_cleanup_cookiestore(void *not_used)
{
    apr_status_t rv = 0;
    ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Cleaning shared cookiestore memory and RMM by shm_cleanup_cookiestore");

    if(cs_rmm_cookiestore) {
        rv = apr_rmm_destroy(cs_rmm_cookiestore);
	if (rv != APR_SUCCESS) {
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Failed to destroy RMM cookiestore");
        	return rv;
	}else{
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Successfully destroyed RMM cookiestore");
        	cs_rmm_cookiestore = NULL;
	}
    }

    if (cs_shm_cookiestore) {
        rv = apr_shm_destroy(cs_shm_cookiestore);
	if (rv != APR_SUCCESS) {
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Failed to destroy shared cookiestore memory");
        	return rv;
	}else{
		ap_log_error(PC_LOG_INFO, NULL, "mod_but_shm.c: (SHM COOKIESTORE) Successfully destroyed shared cookiestore memory");
        	cs_rmm_cookiestore = NULL;
	}
    }
    return rv;
}

apr_rmm_t *find_cs_rmm_cookiestore()
{
	return cs_rmm_cookiestore;
}

apr_rmm_off_t *find_cs_rmm_off_cookiestore()
{
	return off_cookiestore;
}


