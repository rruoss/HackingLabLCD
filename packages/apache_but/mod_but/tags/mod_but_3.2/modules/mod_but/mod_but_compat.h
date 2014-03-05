/* $Id: mod_but_compat.h 34 2008-05-21 07:11:08Z droethli $ */

/*
 * Compatibility hacks.
 *
 * This header must be included after <httpd.h>
 */

#ifndef MOD_BUT_COMPAT_H
#define MOD_BUT_COMPAT_H

/* ap_http_method was renamed to ap_http_scheme */
#if !defined(ap_http_method)
# define ap_http_method ap_http_scheme
#endif

#endif /* MOD_BUT_COMPAT_H */
