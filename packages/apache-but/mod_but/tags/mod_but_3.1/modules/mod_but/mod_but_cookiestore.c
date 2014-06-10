/*#############################################
#
# Title:        mod_but_cookiestore.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/


#include "mod_but.h"

int find_empty_cookiestore_slot(request_rec *r){

	apr_rmm_t *cs_rmm_cookiestore = find_cs_rmm_cookiestore();
	apr_rmm_off_t *off_cookiestore = find_cs_rmm_off_cookiestore();
	int i;

	for (i = 0; i < MOD_BUT_COOKIESTORE_COUNT; i++) {
        	mod_but_cookie_cookiestore *c = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[i]);
		if (c->cookie_slot_used == -1) {
			c->cookie_slot_used = 1;
			return i;
		 }
	}

	// if no more shm available
	apr_table_set(r->notes, "CS_SHM" , "PROBLEM");
	return -1;

}

/*
	return 10 = Cookie with same name exist
	return 20 = New Cookiestore slot created
	return 30 = SHM error
	return 40 = emtpy cookie 
	return 50 = critical error

*/
int store_cookie_in_cookiestore(request_rec *r, int anchor, mod_but_cookie_cookiestore *cs){

		/* CS is the cookie store struct, we have parsed before. This struct contains the cookies we want to save

		*/

	
	apr_rmm_t *cs_rmm_cookiestore = find_cs_rmm_cookiestore();
	apr_rmm_off_t *off_cookiestore = find_cs_rmm_off_cookiestore();

	apr_rmm_t *cs_rmm = find_cs_rmm();
	apr_rmm_off_t *off = find_cs_rmm_off();


	if(apr_table_get(r->notes, "SHMOFFSET")){
		apr_int64_t i;
		mod_but_cookie *c;
		mod_but_cookie_cookiestore *c1;		// current element of the cookistore struct
		mod_but_cookie_cookiestore *c2;		// one element before current cookiestore struct
		mod_but_cookie_cookiestore *c3;  	// one element after current cookiestore struct

		i = apr_atoi64(apr_table_get(r->notes, "SHMOFFSET"));
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: GET SHMOFFSET [%d]", (int)i);


		// C is a pointer to the MOD_BUT_SESSION
		c = apr_rmm_addr_get(cs_rmm, off[i]);

		// C1 is the current cookie struct we want to analyze
		c1 = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[anchor]);

		ap_log_rerror(PC_LOG_INFO, r, "mod_but_output_filter.c: STOREING NEW cookie_name [%s]=[%s] in CookieStore", c1->cookie_name, c1->cookie_value);

		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C: MOD_BUT COOKIE: SESSION NAME = %s", c->session_name);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C: MOD_BUT COOKIE: SESSION VALUE = %s", c->session_value);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C1: CURRENT COOKIE STRUCT FOR ANALYZE: COOKIE NAME = %s", c1->cookie_name);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C1: CURRENT COOKIE STRUCT FOR ANALYZE: COOKIE VALUE = %s", c1->cookie_value);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C1: CURRENT COOKIE STRUCT FOR ANALYZE: COOKIE_NEXT = %d", c1->cookie_next);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C1: CURRENT COOKIE STRUCT FOR ANALYZE: COOKIE_BEFORE = %d", c1->cookie_before);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: CS: COOKIE TO SAVE: COOKIE NAME = %s", cs->cookie_name);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: CS: COOKIE TO SAVE: COOKIE VALUE = %s", cs->cookie_value);	
		


		if (!apr_strnatcmp(cs->cookie_name, c1->cookie_name) && (cs->location_id == c1->location_id)){
			/*
				If we are here, a cookie with the same name is found - we just update it's values
			*/


			/*
				If the cookie value contains "deleted", we want to delete the cookie from the cookiestore
			*/
			if(!apr_strnatcmp(cs->cookie_value, "deleted")){
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: cookie_before = [%d] | cookie_next = [%d]", c1->cookie_before, c1->cookie_next);
				// delete cookie from cookiestore
				if(c1->cookie_before == -1 && c1->cookie_next == -1){
					// first element of cookie chain (element is alone)
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: DELETE FIRST COOKIE FROM EMPTY CHAIN");
					apr_cpystrn(c1->cookie_name, "empty", sizeof(c1->cookie_name));
					apr_cpystrn(c1->cookie_value, "empty", sizeof(c1->cookie_value));
					c1->cookie_next = -1;
					c1->cookie_before = -1;
					c1->cookie_slot_used = -1;
					c->link_to_cookiestore = -1; // set link_to_cookiestore to "-1" into session struct
					c1->location_id = -1;
				} 
				if(c1->cookie_before == -1 && c1->cookie_next >= 0){
					// first element of cookie chain (element is not alone in chain)
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: DELETE FIRST COOKIE FROM NON-EMPTY CHAIN");
					apr_cpystrn(c1->cookie_name, "empty", sizeof(c1->cookie_name));
					apr_cpystrn(c1->cookie_value, "empty", sizeof(c1->cookie_value));
					c1->cookie_before = -1;
					c1->cookie_slot_used = -1;
					c->link_to_cookiestore = c1->cookie_next; // set link_to_cookiestore to the next element 
					c3 = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[c1->cookie_next]);
					c3->cookie_before = -1;
					c1->cookie_next = -1;
					c1->location_id = -1;
				} 
				if(c1->cookie_before >= 0 && c1->cookie_next == -1){
					// last element of cookie chain
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: DELETE LAST COOKIE FROM CHAIN");
					apr_cpystrn(c1->cookie_name, "empty", sizeof(c1->cookie_name));
					apr_cpystrn(c1->cookie_value, "empty", sizeof(c1->cookie_value));
					c1->cookie_next = -1;
					c1->cookie_slot_used = -1;
					// set cookie_next of previous element to -1
					c2 = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[c1->cookie_before]);
					c2->cookie_next = -1; 
					c1->cookie_before = -1;
					c1->location_id = -1;
				} 
				if(c1->cookie_before >= 0 && c1->cookie_next >= 0){
					// element in between of cookie chain
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: DELETE IN-BETWEEN COOKIE FROM CHAIN");
					apr_cpystrn(c1->cookie_name, "empty", sizeof(c1->cookie_name));
					apr_cpystrn(c1->cookie_value, "empty", sizeof(c1->cookie_value));
					c1->cookie_slot_used = -1;
					// set cookie_next of previous element to c1->cookie_next
					c2 = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[c1->cookie_before]);
					c3 = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[c1->cookie_next]);
					c2->cookie_next = c1->cookie_next;
					c3->cookie_before = c1->cookie_before;
					c1->cookie_next = -1;
					c1->cookie_before = -1;
					c1->location_id = -1;
				} 
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: DELETE COOKIE FROM COOKIESTORE");

			} else {
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: UPDATE COOKIE [%s] AND VALUE [%s]", c1->cookie_name, c1->cookie_value);
				apr_cpystrn(c1->cookie_value, cs->cookie_value, sizeof(c1->cookie_value));
				return 10;
			}
		}else{
			/*
				If we are here, the cookie which will be saved has another name then the current name
			*/
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: OUTPUT FILTER: c->cookie_next [%d]", c1->cookie_next);
			if (c1->cookie_next == -1){
				// here we start saving the cookie into the cookiestore
				int cookiestore_offset = find_empty_cookiestore_slot(r);
				if (cookiestore_offset >= 0){
					mod_but_cookie_cookiestore *cs2;

					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: Search empty cookiestore storage %d", cookiestore_offset);
					// C2 is the cookiestore struct, we want to store everything into
					cs2 = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[cookiestore_offset]);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: COOKIESTORE: Save Cookie in store [%s]", cs->cookie_value);
					apr_cpystrn(cs2->cookie_name, cs->cookie_name, sizeof(cs2->cookie_name));
					apr_cpystrn(cs2->cookie_value, cs->cookie_value, sizeof(cs2->cookie_value));
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C1: Update cookie_next [%d]", c1->cookie_next);
					c1->cookie_next = cookiestore_offset;
					cs2->cookie_next=-1;
					cs2->cookie_before = anchor;
					cs2->location_id = cs->location_id;
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: cs2->location_id [%d] at offset [%d]", cs2->location_id, cookiestore_offset);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: C1: CURRENT COOKIE STRUCT FOR ANALYZE: COOKIE_BEFORE = %d", cs2->cookie_before);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: cs2->cookie_next [%d]", cs2->cookie_next);
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: STORE [%s]=[%s]", cs2->cookie_name, cs2->cookie_value);
					return 20;
				} else {
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: CRITICAL ERROR");
					return 50; // INTERNAL_SERVER_ERROR
				}

			}else{
				int status;
				ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: cookie next is defined");
				// recursion for storing the cookie until cookie_next ist not equal -1
				status = store_cookie_in_cookiestore(r, c1->cookie_next, cs);
				if (status == 50){
					ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: CRITICAL ERROR");
					return status;
				}
				return status;
			}
		}
	}
	return 10;
}

void delete_cookiestore_entries_belonging_to_a_deleting_session(request_rec *r, int anchor){

	apr_rmm_t *cs_rmm_cookiestore = find_cs_rmm_cookiestore();
	apr_rmm_off_t *off_cookiestore = find_cs_rmm_off_cookiestore();

	mod_but_cookie_cookiestore *c = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[anchor]);

	if (c->cookie_next == -1){
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: COOKIE STORE: DELETE AT POSITION [%d]", anchor);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: Deleting cookiename [%s]=[%s] from CookieStore", c->cookie_name, c->cookie_value);
		apr_cpystrn(c->cookie_name, "empty", sizeof(c->cookie_name));
		apr_cpystrn(c->cookie_value, "empty", sizeof(c->cookie_value));
		c->cookie_next = -1;
		c->cookie_before = -1;
		c->cookie_slot_used = -1;
	}else{
		int b3;
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: COOKIE STORE: DELETE AT POSITION [%d]", anchor);
		b3=c->cookie_next;
		apr_cpystrn(c->cookie_name, "empty", sizeof(c->cookie_name));
		apr_cpystrn(c->cookie_value, "empty", sizeof(c->cookie_value));
		c->cookie_next = -1;
		c->cookie_before = -1;
		c->cookie_slot_used = -1;
		delete_cookiestore_entries_belonging_to_a_deleting_session(r, b3);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: Delete HEADER @ CS offset %d", c->cookie_next);
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: Deleting cookiestore cookiename [%s] and cookievalue [%s]", c->cookie_name, c->cookie_value);
	}

}



void add_headers_into_request_from_cookiestore(request_rec *r, int anchor){

	//const char* request_cookies;
	mod_but_dir_t *dconfig = ap_get_module_config(r->per_dir_config, &but_module);
	

	apr_rmm_t *cs_rmm_cookiestore = find_cs_rmm_cookiestore();
	apr_rmm_off_t *off_cookiestore = find_cs_rmm_off_cookiestore();

	mod_but_cookie_cookiestore *c = apr_rmm_addr_get(cs_rmm_cookiestore, off_cookiestore[anchor]);
	ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: Analyzing headers from cookie store anchor [%d]", anchor);
	ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: c->cookie_next has: [%d]", c->cookie_next);


	if (dconfig == NULL) {
		ap_log_rerror(PC_LOG_INFO, r, "mod_but_authorization.c: Illegal Directory Config (location_id)");
	}



	if (c->cookie_next == -1){
		// last element of cookie chain (or first element without further elements)
		const char *insert_cookie = NULL;
		const char *new_cookie = NULL;
		const char *existing_cookie = NULL; 
		insert_cookie = (char *)apr_psprintf(r->pool, "%s=%s; ", c->cookie_name, c->cookie_value);
		existing_cookie = apr_table_get(r->notes, "REQUEST_COOKIES"); 

		if ((insert_cookie != NULL) && (c->location_id == dconfig->mod_but_location_id)){
			if (apr_table_get(r->notes, "REQUEST_COOKIES") == NULL) {
				new_cookie=apr_pstrcat(r->pool, insert_cookie, NULL);

			} else {
				new_cookie=apr_pstrcat(r->pool, existing_cookie, insert_cookie, NULL);
				
			}
			apr_table_set(r->notes, "REQUEST_COOKIES", new_cookie);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: ADD COOKIE [%s] into r->notes", apr_table_get(r->notes, "REQUEST_COOKIES"));
		}
		//return;
	}else{
		// last element of cookie chain (or first element without further elements)
		const char *insert_cookie = NULL;
		const char *new_cookie = NULL;
		const char *existing_cookie = NULL; 
		insert_cookie = (char *)apr_psprintf(r->pool, "%s=%s; ", c->cookie_name, c->cookie_value);
		existing_cookie = apr_table_get(r->notes, "REQUEST_COOKIES"); 

		if ((insert_cookie != NULL) && (c->location_id == dconfig->mod_but_location_id)){
			if (apr_table_get(r->notes, "REQUEST_COOKIES") == NULL) {
				new_cookie=apr_pstrcat(r->pool, insert_cookie, NULL);

			} else {
				new_cookie=apr_pstrcat(r->pool, existing_cookie, insert_cookie, NULL);
				
			}
			apr_table_set(r->notes, "REQUEST_COOKIES", new_cookie);
			ap_log_rerror(PC_LOG_INFO, r, "mod_but_cookiestore.c: ADD COOKIE [%s] into r->notes", apr_table_get(r->notes, "REQUEST_COOKIES"));
		}
		add_headers_into_request_from_cookiestore(r, c->cookie_next);
	}
}



