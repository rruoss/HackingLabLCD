/*#############################################
#
# Title:        mod_but_access.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
/* $Id: mod_but_access.c 60 2008-05-30 14:12:41Z droethli $ */

#include "mod_but.h"

/*
 * Parse the first (!) __cookie_try parameter from the request arguments.
 *
 * Returns value of parameter __cookie_try or 0 if it was not found.
 */
int
mod_but_find_cookie_try(request_rec *r)
{
	char *p;
	static const char *param_name = MOD_BUT_COOKIE_TRY;
	ERRLOG_INFO("r->args: [%s]", r->args);

	if (!r->args) {
		return 0;
	}

	p = strstr(r->args, param_name);
	if (p) {
		p += strlen(param_name);
		if (*p == '=') {
			char *cid = (char *)apr_pstrdup(r->pool, p+1);
			if (cid) {
				p = strchr(cid, '&');
				if (p)
					*p = '\0';
				return atoi(cid);
			}
		}
	}
	return 0;
}

