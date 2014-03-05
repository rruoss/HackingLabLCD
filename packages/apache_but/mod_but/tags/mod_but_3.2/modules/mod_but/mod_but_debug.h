/*#############################################
#
# Title:        mod_but_debug.h
# Author:       daniel.roethlisberger@csnc.ch
# Date:         2008-05-20
# Version:      3.2
#
#############################################*/
/* $Id: mod_but_debug.h 65 2008-05-30 17:05:05Z droethli $ */

/*
 * Various debugging/logging helpers.
 */

#ifndef MOD_BUT_DEBUG_H
#define MOD_BUT_DEBUG_H

/* log level shortcuts */
#define PC_LOG_INFO		APLOG_MARK,APLOG_INFO,0
#define PC_LOG_CRIT		APLOG_MARK,APLOG_CRIT,0

/*
 * Convenience logging shortcuts - they assume request_rec *r or server_rec *s
 * are available, depending on variant.
 *
 * *_INFO are used for printf debugging
 * *_CRIT are used for error messages
 *
 * Example:
 *
 *    char *foo = "foo";
 *    char *bar = "bar";
 *    ERRLOG_CRIT("Failed to copy %s to %s", foo, bar);
 *
 * Error log will look like:
 *
 *    [Thu May 29 11:26:18 2008] [crit] [client 127.0.0.1] mod_but_example.c:21: Failed to copy foo to bar
 */

#define ERRLOG_REQ(l, f, ...)	ap_log_rerror(l, r, "%s:%d: " f, __FILE__, __LINE__, ##__VA_ARGS__)
#define ERRLOG_REQ_INFO(f, ...)	ERRLOG_REQ(PC_LOG_INFO, f, ##__VA_ARGS__)
#define ERRLOG_REQ_CRIT(f, ...)	ERRLOG_REQ(PC_LOG_CRIT, f, ##__VA_ARGS__)

#define ERRLOG_SRV(l, f, ...)	ap_log_error(l, s, "%s:%d: " f, __FILE__, __LINE__, ##__VA_ARGS__)
#define ERRLOG_SRV_INFO(f, ...)	ERRLOG_SRV(PC_LOG_INFO, f, ##__VA_ARGS__)
#define ERRLOG_SRV_CRIT(f, ...)	ERRLOG_SRV(PC_LOG_CRIT, f, ##__VA_ARGS__)

#define ERRLOG_INFO(f, ...)	ERRLOG_REQ_INFO(f, ##__VA_ARGS__)
#define ERRLOG_CRIT(f, ...)	ERRLOG_REQ_CRIT(f, ##__VA_ARGS__)

#endif /* MOD_BUT_DEBUG_H */