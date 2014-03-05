/*#############################################
#
# Title:        mod_but_errno.h
# Author:       daniel.roethlisberger@csnc.ch
# Date:         2008-05-20
# Version:      3.2
#
#############################################*/
/* $Id: mod_but_errno.h 58 2008-05-30 14:05:14Z droethli $ */

/*
 * Error number definitions.
 *
 * We use apr_status_t from APR as status type and use the
 * error number range reserved for the application using APR.
 *
 * APR reserves the range APR_OS_START_USERERR ... +50000
 * for the application using APR.  It is therefore safe to
 * intermingle apr_status_t from APR functions with our
 * own STATUS_* status numbers.
 */

#ifndef MOD_BUT_ERRNO_H
#define MOD_BUT_ERRNO_H

/* Make sure our errors are within the APR user error range */
#define MOD_BUT_ERRNO_OFFSET	200
#define NEW_MOD_BUT_STATUS(x)	(APR_OS_START_USERERR + MOD_BUT_ERRNO_OFFSET + (x))

/*
 * mod_but error definitions
 */
#define STATUS_OK		APR_SUCCESS		// success
#define STATUS_ERROR		NEW_MOD_BUT_STATUS(1)	// unspecified error
#define STATUS_ESHM		NEW_MOD_BUT_STATUS(2)	// shared memory error
#define STATUS_EHACKING		NEW_MOD_BUT_STATUS(3)	// hacking alert
#define STATUS_ETIMEOUT		NEW_MOD_BUT_STATUS(4)	// session timeout
#define STATUS_EINACTIVE	NEW_MOD_BUT_STATUS(5)	// session inactivity timeout

#define STATUS_ELOGIN		NEW_MOD_BUT_STATUS(6)	// login required
#define STATUS_ESTEPUP1		NEW_MOD_BUT_STATUS(7)	// stepup 1 required
#define STATUS_ESTEPUP2		NEW_MOD_BUT_STATUS(8)	// stepup 2 required
#define STATUS_EDENIED		NEW_MOD_BUT_STATUS(9)	// access denied

#define STATUS_MATCH		STATUS_OK		// regexp did match
#define STATUS_NOMATCH		NEW_MOD_BUT_STATUS(10)	// regexp did not match

#endif /* MOD_BUT_ERRNO_H */