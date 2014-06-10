/* $Id: mod_replace.c,v 1.1.1.1 2004/04/17 20:30:30 sttesch Exp $ */

/* ====================================================================
 * Copyright (c) 2003, 2004
 *      science + computing ag.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Portions of this software are based upon code written by contributors of 
 * the Apache Software Foundation. This module is based on the original 
 * mod_ext_filter.c from the Apache Webserver (2.0.44), but has been almost 
 * completely rewritten.
 */

/*
 * mod_replace replaces text from the body or the HTTP header of a message. 
 * It works well with the mod_cache and mod_proxy modules.
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_core.h"
#include "apr_buckets.h"
#include "util_filter.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_lib.h"
/** Since we want to use string functions, we have to set this. */
#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_tables.h"
#include "../../srclib/pcre/pcre.h"

/**
 * @file mod_replace.c
 * @brief An Apache filter that replaces text patterns based on regular
 *        expressions with configurable strings. The module has been based on
 *        mod_ext_filter but a great part of it has been rewritten.
 */

/** Size of the buffer for storing subpattern positions and lengths. */
#define RE_VECTOR_SIZE 3072

/** String to use for a request header filter */
#define REQUEST_REPLACE_FILTER "request_replace_filter"

/**
 * Basic server record. Provides a pool for memory allocation and a hash table
 * to store data.
 */
typedef struct replace_server_t {
    /** The pool to allocate memory. */
    apr_pool_t *p;
    /** The hash table to store data. */
    apr_hash_t *h;
} replace_server_t;

/**
 * forward declaration. Otherwise it's not possible to let the structure point 
 * to itself for the next replace_pattern_t
 */ 
typedef struct replace_pattern_t replace_pattern_t;

/**
 * This structure is used to hold all information required to perform a search
 * and replace operation for a single pattern.
 */
struct replace_pattern_t {
    /** The next pattern in the list or NULL if there are no more patterns. */
    replace_pattern_t *next;
    /** The result of the compilation of the regular expression. */
    pcre *pattern;
    /** The result of the inspection (with pcre_study) of the compiled pattern.
     */
    pcre_extra *extra;
    /** The replacement string. */
    char *replacement;
};

/**
 * forward declaration. Otherwise it's not possible to let the structure point
 * to itself for the next replace_pattern_t
 */
typedef struct header_replace_pattern_t header_replace_pattern_t;

/**
 * This structure is used to hold all information required to perform a search
 * and replace operation for a single header pattern.
 */
struct header_replace_pattern_t {
    /** The next pattern in the list or NULL if there are no more patterns. */
    header_replace_pattern_t *next;
    /** The result of the compilation of the regular expression. */
    pcre *pattern;
    /** The result of the inspection (with pcre_study) of the compiled pattern.
     */
    pcre_extra *extra;
    /** The HTTP Header string to perform this operation on. */
    char *header;
    /** The replacement string. */
    char *replacement;
};

/**
 * Structure for the callback function for replacing multiple http headers.
 */
typedef struct header_replace_cb_t {
    /** The table which holds the processed headers. */
    apr_table_t *header_table;
    /** The replacement string. */
    char *replacement;
    /** The compiled pattern. */
    pcre *pattern;
    /** The result from studying the re pattern. */
    pcre_extra *extra;
    /** The request record. */
    request_rec *r;
} header_replace_cb_t;

/**
 * The structure that holds the configuration for the filter.
 *
 * @see ap_filter_type
 * @see replace_pattern_t
 */
typedef struct replace_filter_t {
    /** The name of this filter. */
    const char *name;
    /** The mode for this filter, either filtering outgoing responses or
     * incoming requests (which is not yet supported). 
     */
    enum {INPUT_FILTER=1, OUTPUT_FILTER} mode;
    /** The type of the filter. Is can be anything that is defined in
     * ap_filter_type (util_filter.h). Most useful would be AP_FTYPE_RESOURCE.
     */
    ap_filter_type ftype;
    /** The MIME type which is allowed to be processed by this filter. */
    const char *intype;
    /** If the unlikely event occurs, that this filter changes the MIME type of
     * the processed data.
     */
/** Macro matching all MIME types. */
#define INTYPE_ALL (char *)1
    /** The MIME type of the outgoing data, if different from intype. */
    const char *outtype;
    /** If the pattern matching is to be done case insensitive this has to be
     * set to 1.
     */
    int case_ignore;
    /** The first pattern in the list of patterns that is to be matched against
     * the incoming data. 
     */
    replace_pattern_t *pattern;
    /** A single linked list of patterns that are used to perform replacement 
     * operations on the HTTP header.
     */
    header_replace_pattern_t *header_pattern;
} replace_filter_t;

/**
 * The context structure, which holds information about an ongoing request /
 * response.
 *
 * p is a pool to allocated memory from. A reference to the filter definition,
 * which holds most of the configuration is stored in filter. If noop is set,
 * the filter should not process any request but simply pass the data to the 
 * next filter. Finally, the bucket brigade bb is used to save all incoming
 * bucket until the end of the data has been reached, which then can be
 * processed in one turn.
 */
typedef struct replace_ctx_t {
    /** A pool to allocate memory for structures and similar things. */
    apr_pool_t *p;
    /** The configuration of the filter. */
    replace_filter_t *filter;
    /** Flag to check if the filter should process this request (noop = 0) or
     * send the incoming data immediately to the next filter (noop = 1).
     */
    int noop;
    /** The brigade which is used to store the incomplete incoming data until
     * all data is ready to be processed.
     */
    apr_bucket_brigade *bb;
} replace_ctx_t;

/**
 * Tell Apache that there is a module named replace_module.
 */
module AP_MODULE_DECLARE_DATA replace_module;

/**
 * Global variable which holds the default server record.
 */
static const server_rec *main_server;

/**
 * Forward declaration for the output filter.
 */
static apr_status_t replace_output_filter(ap_filter_t *, apr_bucket_brigade *);

/**
 * Forward declaration for the input filter.
 */
static apr_status_t replace_input_fixup(request_rec *r);

/**
 * Initialisation of the module. The main server record is set to the server
 * specified by Apache.
 */ 
static int replace_init(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, 
                        server_rec *main_s)
{
    main_server = main_s;
    return OK;
}

/* Register the filter with the replace_init() function as initializer for this
 * filter.
 */
static void register_hooks(apr_pool_t *p)
{
    ap_hook_post_config(replace_init, NULL, NULL, APR_HOOK_FIRST);
    ap_hook_fixups(replace_input_fixup, NULL, NULL, APR_HOOK_LAST);
}

/**
 * Creates a new config for the specified server.
 */
static void *create_replace_server_conf(apr_pool_t *p, server_rec *s)
{
    replace_server_t *conf;

    conf = (replace_server_t *)apr_pcalloc(p, sizeof(replace_server_t));
    conf->p = p;
    conf->h = apr_hash_make(conf->p);
    return conf;
}

/**
 * This function gets called whenever there is a 'ReplacePattern' in the config
 * file and it's syntax is correct (that is, it takes three arguments). Return
 * NULL if everything went alright, otherwise an error message.
 * 
 * @param cmd           The command record filled with general information 
 *                      about the environment.
 * @param dummy         To be ignored.
 * @param name          The name of the filter.
 * @param pattern_str   The regular expression for the pattern matching.
 * @param replace       The replacement string.
 */
static const char *add_pattern(cmd_parms *cmd, void *dummy, 
                               const char *name, const char *pattern_str, 
                               const char *replace)
{
    replace_server_t *conf; // the server configuration (hashtable)
    replace_filter_t *filter; 
                            // the filter configuration
    replace_pattern_t *pattern; 
                            // the pattern to add
    replace_pattern_t *previous;
                            // the previous pattern, if any
    replace_pattern_t backup;                            
    pcre *re;               // the regular expression
    pcre_extra *pe;         // data from studying the pattern
    const char *error;      // error text for the failed regex compilation
    int error_offset;       // offset of the regex compilation error, if any
    int rc;                 // return count of the regex matching
    int i;                  // counter
    int rv;                 // return value for generic function calls
    int flags = 0;          // the flags for the regex matching

    /* Get the configuration record and add the regex and replacement pattern.
     */
    conf = ap_get_module_config(cmd->server->module_config, &replace_module);
    if (conf == NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Illegal server record", NULL, NULL);
    }
    filter = (replace_filter_t*)apr_hash_get(conf->h, name, 
                                            APR_HASH_KEY_STRING);
    if (filter == NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Unknown filter definition for replace filter");
    }

    /* Check if we have to set the flag for case insensitive matching. */
    if (filter->case_ignore == 1) {
        flags |= PCRE_CASELESS;
    }

    /* Compile the pattern. */
    re = pcre_compile(pattern_str, flags, &error, &error_offset, NULL);

    /* Return ungraceful if the compilation of the regex failed. */
    if (re == NULL) {
        return apr_pstrcat(cmd->temp_pool, 
                           "Error compiling regular expression: ", error,
                           NULL);
    }
    
    /* Study the pattern. This is done for performance improvement, but most of
     * the time it doesn't speed up things, since the return value is simply
     * NULL. 
     */
    pe = pcre_study(re, 0, &error);
    if (error != NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Error studying compiled pattern: ", error, NULL);
    }

    /* Check for an already existing pattern. */
    pattern = filter->pattern;
    previous = NULL;
    
    /* Find the last pattern in the list. */
    while (pattern && pattern->next != NULL) {
        previous = pattern;
        pattern = pattern->next;
    }

    /* If there has been no pattern at all, create one. Otherwise save the last
     * pattern and create a new one.
     */
    if (!pattern) {
        pattern = (replace_pattern_t *)apr_pcalloc(conf->p,
                                                   sizeof(replace_pattern_t));
        filter->pattern = pattern;
    } else {
        previous = pattern;
        pattern = (replace_pattern_t *)apr_pcalloc(conf->p,
                                                   sizeof(replace_pattern_t));
    }

    /* Assign the values to the structure and add the pattern to the list. */
    pattern->pattern = re;
    pattern->extra = pe;
    pattern->replacement = apr_pstrdup(conf->p, replace);
    pattern->next = NULL;

    if (previous) {
        previous->next = pattern;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "Filter %s: Added pattern \"%s\"", 
                 name, pattern_str);

    return NULL;
}

/**
 * This function gets called whenever there is a 'HeaderReplacePattern' in the 
 * config file.
 * Returns NULL if everything went alright, otherwise an error message.
 *
 * @param cmd           The command record filled with general information
 *                      about the environment.
 * @param dummy         To be ignored.
 * @param args          The arguments passed from the pattern definition. Must
 *                      be in the following order: name, header, pattern,
 *                      replacement string.
 */
static const char *add_header_pattern(cmd_parms *cmd, 
                                      void *dummy, 
                                      const char *args)
{
    const char *name;       // the filter name
    const char *header;     // the HTTP header field to match
    const char *pattern_str;// the textual representation of the pattern
    const char *replace;    // the replacement string
    
    replace_server_t *conf; // the server configuration (hashtable)
    replace_filter_t *filter; 
                            // the filter configuration
    header_replace_pattern_t *pattern; 
                            // the pattern to add
    header_replace_pattern_t *previous;
                            // the previous pattern, if any
    header_replace_pattern_t backup;                            
    pcre *re;               // the regular expression
    pcre_extra *pe;         // data from studying the pattern
    const char *error;      // error text for the failed regex compilation
    int error_offset;       // offset of the regex compilation error, if any
    int rc;                 // return count of the regex matching
    int i;                  // counter
    int rv;                 // return value for generic function calls
    int flags = 0;          // the flags for the regex matching

    /* Get the configuration record */
    conf = ap_get_module_config(cmd->server->module_config, &replace_module);
    if (conf == NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Illegal server record", NULL, NULL);
    }

    /*
     * Parse the arguments.
     */

    /* Extract the name of the filter and check for its existence. */
    name = ap_getword_white(cmd->pool, &args);
    if (!apr_hash_get(conf->h, name, APR_HASH_KEY_STRING)) {
      return "ReplaceFilter not defined";
    }

    /* Extract the header field. */
    header = ap_getword_conf(cmd->pool, &args);
    if (!header || strlen(header) == 0) {
        return "Header field missing";
    }

    /* Extract the regex pattern */
    pattern_str = ap_getword_conf(cmd->pool, &args);
    if (!pattern_str || strlen(pattern_str) == 0) {
        return "Pattern definition missing";
    }

    if (!args || !strlen(args) > 0) {
        return "Replacement pattern missing";
    }

    /* Extract the replacement string */
    replace = ap_getword_conf(cmd->pool, &args);
    if (!replace) {
        return "Replacement pattern missing";
    }

    /* Check for additional, illegal configuration directives */
    if (args && strlen(args) > 0) {
        return apr_psprintf(cmd->temp_pool, "Illegal conf directive: \"%s\"", 
                            args);
    }
    
    /* Get the filter definition */
    filter = (replace_filter_t*)apr_hash_get(conf->h, name, 
                                            APR_HASH_KEY_STRING);
    if (filter == NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Unknown filter definition for replace filter");
    }


    /* Check if we have to set the flag for case insensitive matching. */
    if (filter->case_ignore == 1) {
        flags |= PCRE_CASELESS;
    }

    /* Compile the pattern. */
    re = pcre_compile(pattern_str, flags, &error, &error_offset, NULL);

    /* Return ungraceful if the compilation of the regex failed. */
    if (re == NULL) {
        return apr_pstrcat(cmd->temp_pool, 
                           "Error compiling regular expression: ", error,
                           NULL);
    }
    
    /* Study the pattern. This is done for performance improvement, but most of
     * the time it doesn't speed up things, since the return value is simply
     * NULL. 
     */
    pe = pcre_study(re, 0, &error);
    if (error != NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Error studying compiled pattern: ", error, NULL);
    }

    /* Check for an already existing pattern. */
    pattern = filter->header_pattern;
    previous = NULL;
    
    /* Find the last pattern in the list. */
    while (pattern && pattern->next != NULL) {
        previous = pattern;
        pattern = pattern->next;
    }

    /* If there has been no pattern at all, create one. Otherwise save the last
     * pattern and create a new one.
     */
    if (!pattern) {
        pattern = (header_replace_pattern_t *)apr_pcalloc(conf->p,
                                                   sizeof(header_replace_pattern_t));
        filter->header_pattern = pattern;
    } else {
        previous = pattern;
        pattern = (header_replace_pattern_t *)apr_pcalloc(conf->p,
                                                   sizeof(header_replace_pattern_t));
    }

    /* Assign the values to the structure and add the pattern to the list. */
    pattern->pattern = re;
    pattern->extra = pe;
    pattern->replacement = apr_pstrdup(conf->p, replace);
    pattern->header = apr_pstrdup(conf->p, header);
    pattern->next = NULL;

    if (previous) {
        previous->next = pattern;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "Filter %s: Added header pattern \"%s\"", name, pattern_str);
        
    return NULL;
}

/**
 * This function gets called whenever there is a 'RequestHeaderPattern' in the
 * config file and it's syntax is correct (that is, it takes three arguments).
 * Returns NULL if everything went alright, otherwise an error message.
 *
 * @param cmd           The command record filled with general information
 *                      about the environment.
 * @param dummy         To be ignored.
 * @param name          The name of the filter.
 * @param header        The header field name.
 * @param pattern_str   The regular expression for the pattern matching.
 * @param replace       The replacement string.
 */
static const char *request_header_pattern(cmd_parms *cmd,
                                          void *dummy,
                                          const char *header,
                                          const char *pattern_str,
                                          const char *replace) {

    replace_server_t *conf; // the server configuration (hashtable)
    replace_filter_t *filter;
                            // the filter configuration
    header_replace_pattern_t *pattern;
                            // the pattern to add
    header_replace_pattern_t *previous;
                            // the previous pattern, if any
    header_replace_pattern_t backup;
    pcre *re;               // the regular expression
    pcre_extra *pe;         // data from studying the pattern
    const char *error;      // error text for the failed regex compilation
    int error_offset;       // offset of the regex compilation error, if any
    int rc;                 // return count of the regex matching
    int i;                  // counter
    int rv;                 // return value for generic function calls
    int flags = 0;          // the flags for the regex matching

    conf = ap_get_module_config(cmd->server->module_config, &replace_module);
    if (conf == NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Illegal server record", NULL, NULL);
    }

    /** Look for an existing filter */
    filter = (replace_filter_t*)apr_hash_get(conf->h, REQUEST_REPLACE_FILTER,
                                            APR_HASH_KEY_STRING);
    /** If no filter exists, create one */
    if (filter == NULL) {
        filter = (replace_filter_t *)apr_pcalloc(conf->p, 
                                                 sizeof(replace_filter_t));
        filter->name = REQUEST_REPLACE_FILTER;
        filter->mode = INPUT_FILTER;
        filter->ftype = AP_FTYPE_RESOURCE;
        filter->pattern = NULL;
        filter->case_ignore = 1;
        apr_hash_set(conf->h, REQUEST_REPLACE_FILTER, APR_HASH_KEY_STRING, 
                     filter);
    }
    
    /* Check if we have to set the flag for case insensitive matching. */
    if (filter->case_ignore == 1) {
        flags |= PCRE_CASELESS;
    }

    /* Compile the pattern. */
    re = pcre_compile(pattern_str, flags, &error, &error_offset, NULL);

    /* Return ungraceful if the compilation of the regex failed. */
    if (re == NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Error compiling regular expression: ", error,
                           NULL);
    }

    /* Study the pattern. This is done for performance improvement, but most of
     * the time it doesn't speed up things, since the return value is simply
     * NULL.
     */
    pe = pcre_study(re, 0, &error);
    if (error != NULL) {
        return apr_pstrcat(cmd->temp_pool,
                           "Error studying compiled pattern: ", error, NULL);
    }

    /* Check for an already existing pattern. */
    pattern = filter->header_pattern;
    previous = NULL;

    /* Find the last pattern in the list. */
    while (pattern && pattern->next != NULL) {
        previous = pattern;
        pattern = pattern->next;
    }

    /* If there has been no pattern at all, create one. Otherwise save the last
     * pattern and create a new one.
     */
    if (!pattern) {
        pattern = (header_replace_pattern_t *)apr_pcalloc(conf->p,
                    sizeof(header_replace_pattern_t));
        filter->header_pattern = pattern;
    } else {
        previous = pattern;
        pattern = (header_replace_pattern_t *)apr_pcalloc(conf->p,
                    sizeof(header_replace_pattern_t));
    }

    /* Assign the values to the structure and add the pattern to the list. */
    pattern->pattern = re;
    pattern->extra = pe;
    pattern->replacement = apr_pstrdup(conf->p, replace);
    pattern->header = apr_pstrdup(conf->p, header);
    pattern->next = NULL;

    if (previous) {
        previous->next = pattern;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, cmd->server,
                 "Header/In: Added pattern \"%s\"", pattern_str);

    return NULL;
}

/**
 * Gets called whenever there is a "ReplaceFilterDefine" line in the config
 * file. The method creates a new configuration (replace_filter_t) for the
 * server (available through cmd->server). Returns an error message if things
 * didn't work out.
 *
 * @param cmd   The command record that holds the general data for the
 *              environment.
 * @param dummy To be ignored.
 * @param args  The arguments from the filter definition (everything following
 *              ReplaceFilterDefine.
 * @see cmd_parms 
 */
static const char *define_filter(cmd_parms *cmd, void *dummy, const char *args)
{
    replace_server_t *conf = ap_get_module_config(cmd->server->module_config,
                                             &replace_module);
    const char *token;
    const char *name;
    replace_filter_t *filter;

    /* Extract the name of the filter. */
    name = ap_getword_white(cmd->pool, &args);
    if (!name) {
        return "Filter name not found";
    }

    /* Check if there is another filter by the same name. */
    if (apr_hash_get(conf->h, name, APR_HASH_KEY_STRING)) {
        return apr_psprintf(cmd->pool, "Replace Filter %s is already defined",
                            name);
    }
    
    /* Create a new filter configuration and populate the filter configuration 
     * with default values.
     */
    filter = (replace_filter_t *)apr_pcalloc(conf->p, sizeof(replace_filter_t));
    filter->name = name;
    filter->mode = OUTPUT_FILTER;
    filter->ftype = AP_FTYPE_RESOURCE;
    filter->pattern = NULL;
    filter->case_ignore = 0;
    apr_hash_set(conf->h, name, APR_HASH_KEY_STRING, filter);

    /* Parse the remaining arguments. */
    while (*args) {
        /* Ignore whitespaces. */
        while (apr_isspace(*args)) {
            ++args;
        }

        /* Set the filter mode. */
        if (!strncasecmp(args, "mode=", 5)) {
            args += 5;
            token = ap_getword_white(cmd->pool, &args);
            if (!strcasecmp(token, "output")) {
                filter->mode = OUTPUT_FILTER;
            }
            else if (!strcasecmp(token, "input")) {
                filter->mode = INPUT_FILTER;
            }
            else {
                return apr_psprintf(cmd->pool, "Invalid mode: `%s'",
                                    token);
            }
            continue;
        }

        /* Set the filter type. */
        if (!strncasecmp(args, "ftype=", 6)) {
            args += 6;
            token = ap_getword_white(cmd->pool, &args);
            filter->ftype = atoi(token);
            continue;
        }

        /* MIME type for incoming data. */
        if (!strncasecmp(args, "intype=", 7)) {
            args += 7;
            filter->intype = ap_getword_white(cmd->pool, &args);
            continue;
        }

        /* MIME type for outgoing data, if different from intype. */
        if (!strncasecmp(args, "outtype=", 8)) {
            args += 8;
            filter->outtype = ap_getword_white(cmd->pool, &args);
            continue;
        }

        /* check if the regular expression is to be handled case sensitive or
         * not.
         */
        if (!strncasecmp(args, "caseignore", 10)) {
            token = ap_getword_white(cmd->pool, &args);
            if (!strncasecmp(token, "caseignore", 10)) {
                filter->case_ignore = 1;
            } else {
                return apr_psprintf(cmd->pool, "mangled argument `%s'",
                                    token);
            }
            continue;
        }
        
        /* If there is any other argument than the already checked ones, return
         * with an error message.
         */
        return apr_psprintf(cmd->pool, "Unexpected parameter: `%s'",
                            args);
    }

    /* parsing is done...  register the filter 
     */
    if (filter->mode == OUTPUT_FILTER) {
        /* XXX need a way to ensure uniqueness among all filters */
        if (!ap_register_output_filter(filter->name, replace_output_filter, 
                                       NULL, filter->ftype)) {
            return apr_psprintf(cmd->pool, 
                                "Unable to register output filter '%s'",
                                filter->name);
        }
    }
    else {
        ap_assert(1 != 1); /* we set the field wrong somehow */
    }

    return NULL;
}

/**
 * Definition on how to react if the specified commands (ReplaceFilterDefine,
 * ReplacePattern, HeaderReplacePattern) occur in the configuration file.
 */
static const command_rec cmds[] =
{
    /** Definition of a new filter. The directive is allowed everywhere
     * (RSRC_CONF) and the method define_filter is to be called. The directive
     * takes any number of arguments which get passed "raw" to the method.
     */
    AP_INIT_RAW_ARGS("ReplaceFilterDefine",
                     define_filter,
                     NULL,
                     RSRC_CONF,
                     "Define a replace filter"),
    /** Add a replacement pattern to the specified filter. The directive takes
     * three arguments: the name of the filter, the regular expression for the
     * pattern and the replacement string. This directive is also allowed
     * everywhere (RSRC_CONF) and add_pattern is called.
     */
    AP_INIT_TAKE3("ReplacePattern",
                  add_pattern,
                  NULL,
                  RSRC_CONF,
                  "usage: ReplacePattern filtername pattern replacement"),
    /** Add a header replacement pattern to the specified filter. This 
     * directive takes four arguments: the name of the filter, the name of the 
     * header field, the regular expression for the pattern and its replacement
     * string. 
     */
    AP_INIT_RAW_ARGS("HeaderReplacePattern",
		   add_header_pattern,
		   NULL,
		   RSRC_CONF,
		   "usage: HeaderReplacePattern filtername header pattern replacement"),
    /** Add a REQUEST header pattern. This pattern is processed in a different
     * way than the other patterns, since it has to be processed before the 
     * proxy module catches the request. This filter is independet from any 
     * filter you set with Set(In|Out)putFilter and ALWAYS active when defined.
     */
    AP_INIT_TAKE3("RequestHeaderPattern",
           request_header_pattern,
           NULL,
           RSRC_CONF,
           "usage: RequestHeaderPattern header pattern replacement"),
    /** Terminator. */
    {NULL}
};

/**
 * Callback function that is used to look for a filter. Returns the
 * configuration record for this filter, if the name and server record matches.
 *
 * @param s     The server record which looks for a filter.
 * @param fname The filter name.
 */
static replace_filter_t *find_filter_def(const server_rec *s, const char *fname)
{
    replace_server_t *sc;
    replace_filter_t *f;

    sc = ap_get_module_config(s->module_config, &replace_module);
    f = apr_hash_get(sc->h, fname, APR_HASH_KEY_STRING);
    if (!f && s != main_server) {
        s = main_server;
        sc = ap_get_module_config(s->module_config, &replace_module);
        f = apr_hash_get(sc->h, fname, APR_HASH_KEY_STRING);
    }
    return f;
}

/* Internal functions. */

/** 
 * Extract the substring from s starting at "from" for "len" characters.
 * Returns the extracted substring or NULL.
 * 
 * @param s     The string from which to extract.
 * @param from  The position in s where the substring starts.
 * @param len   The length of the substr.
 */
static char *substr(const char *s, int from, int len, request_rec *r) {
    char *str;

    /* Sanity checking. */
    if (len < 1 || from < 0) 
        return NULL;

    /* Allocate memory for the operation. */
    str = malloc((size_t)(len + 1));

    /* Copy the string, add a trailing zero and return the result. */
    memcpy(str, (s + from), (size_t)(len));
    str[len] = 0;
    return str;
}

/**
 * Replace the first two characters of s with the string in c. Returns the
 * corrected string.
 *
 * @param s             The original string.
 * @param c             The string which replaces the first two characters in s.
 * @param len_orig      The length of the original string (s).
 * @param len_replace   The length of the replacement string (c).
 */
static char *substr_replace(char *s, const char *c, int len_orig, 
                            int len_replace) {

    char *tmp;
    /* allocate memory to save the string after the occurence (-2 for the token
     * in front of the string, +1 for the trailing zero). 
     */
    tmp = malloc(len_orig - 1);
    memcpy(tmp, (s + 2), len_orig - 1);
    
    memcpy(s, c, len_replace);

    memcpy((s + len_replace), tmp, len_orig - 1);

    return s;
}

/**
 * Callback function to extract multiple HTTP headers from the outgoing header 
 * and change them a little bit. (borrowed from server/util_script.c)
 */
static int replace_header_cb(void *v, const char *key, const char *val)
{
    header_replace_cb_t *data;
    data = (header_replace_cb_t *) v;
    // do replacement and finally add the new value to the table
    int len = strlen(val);
    int rc = 0;
    int re_vector[RE_VECTOR_SIZE];  // 3 elements per matched pattern
    request_rec *r;
    r = data->r;

    rc = pcre_exec(data->pattern, data->extra, val, 
                   len, 0, 0, re_vector, RE_VECTOR_SIZE);

    if (rc < 0 && rc != PCRE_ERROR_NOMATCH) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, 
                      "Matching Error %d", rc);
        return rc;
    }

    if (rc == 0) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, 
                      "PCRE output vector too small (%d)", 
                      RE_VECTOR_SIZE/3-1);
    }

    /* If the result count is greater than 0 then there are
     * matches in the data string. Thus we try to replace those
     * strings with the user provided string.
     */
    if (rc > 0) {
        char *replacement;
        char *prefix, *postfix;
        replacement = apr_pstrcat(r->pool, data->replacement, 
                                  NULL);
        prefix = apr_pcalloc(r->pool, re_vector[0] + 1);
        if (prefix == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Unable to allocate memory for prefix");
            return -1;
        }
        memcpy(prefix, val, (size_t)re_vector[0]);
    
        postfix = apr_pcalloc(r->pool, len);
        if (postfix == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                          "Unable to allocate memory for postfix");
            return -1;
        }
        memcpy(postfix, (val + re_vector[1]), len - re_vector[1]);
        val = apr_pstrcat(r->pool, prefix, replacement, postfix, NULL);
    }
    apr_table_addn(data->header_table, key, val);
    return 1;
}

/**
 * The output filter routine. This one gets called whenever a response is
 * generated that passes this filter. Returns APR_SUCCESS if everything works
 * out.
 *
 * @param f     The filter definition.
 * @param bb    The bucket brigade containing the data.
 */
static apr_status_t replace_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
{
    request_rec *r = f->r;
    conn_rec *c = r->connection;
    replace_ctx_t *ctx = f->ctx;
    apr_bucket *b;
    apr_size_t len;
    const char *data;
    const char *header;
    apr_status_t rv;
    int re_vector[RE_VECTOR_SIZE];  // 3 elements per matched pattern
    replace_pattern_t *next;
    header_replace_pattern_t *next_header;
    int modified = 0;               // flag to determine if a replacement has
                                    // occured.

    if (!ctx) {
        /* Initialize context */
        ctx = apr_pcalloc(f->r->pool, sizeof(replace_ctx_t));
        f->ctx = ctx;
        ctx->bb = apr_brigade_create(r->pool, c->bucket_alloc);
    }

    /* parse config settings */
    
    /* look for the user-defined filter */
    ctx->filter = find_filter_def(f->r->server, f->frec->name);
    if (!ctx->filter) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, f->r,
                      "couldn't find definition of filter '%s'",
                      f->frec->name);
        return APR_EINVAL;
    }
    ctx->p = f->r->pool;
    if (ctx->filter->intype &&
        ctx->filter->intype != INTYPE_ALL) {
        if (!f->r->content_type) {
            ctx->noop = 1;
        }
        else {
            const char *ctypes = f->r->content_type;
            const char *ctype = ap_getword(f->r->pool, &ctypes, ';');

            if (strcasecmp(ctx->filter->intype, ctype)) {
                /* wrong IMT for us; don't mess with the output */
                ctx->noop = 1;
            }
        }
    }

    /* exit immediately if there are indications that the filter shouldn't be
     * executed.
     */
    if (ctx->noop == 1) {
        ap_pass_brigade(f->next, bb);
        return APR_SUCCESS;
    }

    /**
     * Loop through the configured header patterns.
     */
    for (next_header = ctx->filter->header_pattern;
         next_header != NULL;
         next_header = next_header->next) {

        // create a separate table with the requested HTTP header entries and
        // unset those headers in the original request.
        apr_table_t *header_table;
        header_table = apr_table_make(r->pool, 2);
    	// create a data structure for the callback function
    	header_replace_cb_t *hrcb;
    	hrcb = apr_palloc(r->pool, sizeof(header_replace_cb_t));
    	hrcb->header_table = header_table;
	    hrcb->pattern = next_header->pattern;
    	hrcb->extra = next_header->extra;
	    hrcb->replacement = next_header->replacement;
    	hrcb->r = r;
	    // pass any header that is defined to be processed to the callback 
    	// function and unset those headers in the original outgoing record.
        apr_table_do(replace_header_cb, hrcb, r->headers_out, 
                     next_header->header, NULL);
        // only touch the header if the changed header table is not empty.
        if (!apr_is_empty_table(header_table)) {
            apr_table_unset(r->headers_out, next_header->header);
            // overlay the original header table with the new one to reintegrate
            // the changed headers.
            r->headers_out = apr_table_overlay(r->pool, r->headers_out, 
                                               header_table);
        }
    }

    /* Not nice but neccessary: Unset the ETag , because we cannot adjust the 
     * value correctly, because we do not know how.
     */
    apr_table_unset(f->r->headers_out, "ETag"); 

    int eos = 0;        // flag to check if an EOS bucket is in the brigade.
    apr_bucket *eos_bucket;
                        // Backup for the EOS bucket.

    /* Interate through the available data. Stop if there is an EOS */

   for (b = APR_BRIGADE_FIRST(bb); b != APR_BRIGADE_SENTINEL(bb); b = APR_BUCKET_NEXT(b)) {
        if (APR_BUCKET_IS_EOS(b)) {
            eos = 1;
            ap_save_brigade(f, &ctx->bb, &bb, ctx->p);
            APR_BUCKET_REMOVE(b);
            eos_bucket = b;
            break;
        }
    }


    /* If the iteration over the brigade hasn't found an EOS bucket, just save
     * the brigade and return.
     */
    if (eos != 1) {
        ap_save_brigade(f, &ctx->bb, &bb, ctx->p);
        return APR_SUCCESS;
    }

    if ((rv = apr_brigade_pflatten(ctx->bb, (char **)&data, &len, ctx->p)) 
        != APR_SUCCESS) { 
        /* Return if the flattening didn't work. */
        return rv;
    } else {
        /* Remove the original data from the bucket brigade. Otherwise it would
         * be passed twice (original data and the processed, flattened copy) to
         * the next filter.
         */
        apr_brigade_cleanup(ctx->bb);
    }

    /* Good cast, we just tested len isn't negative or zero */
    if (len > 0) {

        /* start checking for the regex's. */
        for (next = ctx->filter->pattern; 
             next != NULL; 
             next = next->next)
        {
            int rc = 0;
            int offset = 0;

            /* loop through the configured patterns */
            do {
                rc = pcre_exec(next->pattern, next->extra, data, 
                               len, offset, 0,
                               re_vector, RE_VECTOR_SIZE);
                               
                if (rc < 0 && rc != PCRE_ERROR_NOMATCH) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, 
                                  "Matching Error %d", rc);
                    return rc;
                }

                /* This shouldn´t happen */
                if (rc == 0) {
                    ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
                                  "PCRE output vector too small (%d)", 
                                  RE_VECTOR_SIZE/3-1);
                }

                /* If the result count is greater than 0 then there are
                 * matches in the data string. Thus we try to replace those
                 * strings with the user provided string.
                 */
                if (rc > 0) {
                    char *prefix;   // the string before the matching part.
                    char *postfix;  // the string after the matching part.
                    char *newdata;  // the concatenated string of prefix,
                                    // the replaced string and postfix.
                    char *replacement;
                                    // the string with the data to replace
                                    // (after the subpattern processing has
                                    // been done).
                    char *to_replace[10];
                                    // the string array containing the
                                    // strings that are to be replaced.
                    int match_diff; // the difference between the matching
                                    // string and its replacement.
                    int x;          // a simple counter.
                    char *pos;      // the starting position within the
                                    // replacement string, where there is a
                                    // subpattern to replace.

                    /* start with building the replacement string */
                    replacement = apr_pstrcat(ctx->p, next->replacement,
                                              NULL);

                    /* look for the subpatterns \0 to \9 */

                    for (x = 0; x < rc && x < 10; x++) {
                        /* extract the x'ths subpattern */
                        to_replace[x] = substr(data, re_vector[x*2],
                                               re_vector[x*2+1] -
                                               re_vector[x*2], r); 

                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                                      "Found match: %s", to_replace[x]);
                        
                        /* the token ( \0 to \9) we are looking for */
                        char *token = apr_pstrcat(ctx->p, "\\",
                                                apr_itoa(ctx->p, x), NULL);
                        /* allocate memory for the replacement operation */
                        char *tmp;
                        if (!to_replace[x] || strlen(to_replace[x]) < 2) {
                            tmp = malloc(strlen(replacement) + 1);
                        } else {
                            tmp = malloc(strlen(replacement) - 1 +
                                         strlen(to_replace[x]));
                        }
                        /* copy the replacement string to the new
                         * location.
                         */
                        memcpy(tmp, replacement, strlen(replacement) + 1);
                        replacement = tmp;
                        /* try to replace each occurence of the token with
                         * its matched subpattern. */
                        pos = ap_strstr(replacement, token);
                        while (pos) { 
                            if (!to_replace[x]) {
                                break;
                            }
                            substr_replace(pos, to_replace[x],
                                           strlen(pos), 
                                           strlen(to_replace[x]));
                            if (strlen(to_replace[x]) < 2) {
                                tmp = malloc(strlen(replacement) + 1);
                            } else {
                                tmp = malloc(strlen(replacement) - 1 + 
                                             strlen(to_replace[x]));
                            }
                            memcpy(tmp, replacement, 
                                   strlen(replacement) + 1);
                            /* clean up. */
                            free(replacement);
                            replacement = tmp; 
                            pos = ap_strstr(replacement, token);
                        }
                    }

                    match_diff = strlen(replacement) -
                                 (re_vector[1] - re_vector[0]);

                    /* Allocate memory for a buffer to copy the first part
                     * of the data string up to (but not including) the
                     * the matching pattern.
                     */
                    prefix = apr_pcalloc(ctx->p, re_vector[0] + 1);
                    if (prefix == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Unable to allocate memory for prefix",
                            NULL);
                        return -1;
                    }

                    /* Copy the string from the offset (beginning of
                     * pattern matching) to the first occurence of the
                     * pattern and add a trailing \0.
                     */
                    memcpy(prefix, data, (size_t)re_vector[0]); 

                    /* Copy the string from the end of the pattern to the
                     * end of the data string itself.
                     */
                    postfix = apr_pcalloc(ctx->p, len);
                    if (postfix == NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "Unable to allocate memory for postfix",
                            NULL);
                        return -1;
                    }
                    
                    memcpy(postfix, 
                           (data + re_vector[1]),
                           len - re_vector[1]);
                    
                    /* Create the new data string, replace the old one
                     * and clean up.
                     */
                    newdata = apr_pstrcat(ctx->p, prefix, 
                                          replacement, postfix, 
                                          NULL);
                    /* update the point of the data and free the allocated
                     * memory for the replacement string.
                     */
                    data = newdata;
                    free(replacement);

                    /* Calculate the new offset in the data string, where
                     * the new matching round is to begin.
                     */
                    offset = re_vector[1] + match_diff; 
                    len += match_diff;
                    modified = 1;
                }
            } while (rc > 0);
        }
        /* Adjust the real length of the processed data. */
        if (apr_table_get(f->r->headers_out, "Content-Length") != NULL) {
            apr_table_set(f->r->headers_out, "Content-Length",
                apr_itoa(ctx->p, len));
        }
        /* If an Entity Tag is set, change the mtime and generate a new ETag.*/
        if (apr_table_get(f->r->headers_out, "ETag") != NULL) {
           r->mtime = time(NULL);
           ap_set_etag(r);
        }
    }
    /* Create a new bucket with the processed data, insert that one into our
     * brigade, then insert the saved EOS bucket at the end of the brigade
     * and pass the brigade to the next filter.
     */
    APR_BRIGADE_INSERT_TAIL(ctx->bb, apr_bucket_transient_create(data, len, apr_bucket_alloc_create(ctx->p)));
    APR_BRIGADE_INSERT_TAIL(ctx->bb, eos_bucket);
    ap_pass_brigade(f->next, ctx->bb);

    return APR_SUCCESS;
}


/**
 * Fixup routine for request header processing.
 *
 * @params r    The request record
 */
static apr_status_t replace_input_fixup(request_rec *r)
{
    replace_server_t *conf = ap_get_module_config(r->server->module_config,
                                                  &replace_module);
    replace_filter_t *filter = (replace_filter_t*)apr_hash_get(conf->h, 
                                    REQUEST_REPLACE_FILTER,
                                    APR_HASH_KEY_STRING);
    header_replace_pattern_t *pattern;
    /* Exit if there is no filter definition. */
    if (filter == NULL) {
        return DECLINED;
    }

    /* Loop the configured patterns */
    for (pattern = filter->header_pattern; pattern != NULL; pattern = pattern->next) {
        apr_table_t *header_table = apr_table_make(r->pool, 2);
        header_replace_cb_t *hrcb = apr_palloc(r->pool,
                                               sizeof(header_replace_cb_t));
        hrcb->header_table = header_table;
        hrcb->pattern = pattern->pattern;
        hrcb->extra = pattern->extra;
        hrcb->replacement = pattern->replacement;
        hrcb->r = r;
        apr_table_do(replace_header_cb, hrcb, r->headers_in,
                     pattern->header, NULL);
        if (!apr_is_empty_table(header_table)) {
            apr_table_unset(r->headers_in, pattern->header);
            r->headers_in = apr_table_overlay(r->pool, r->headers_in,
                                              header_table);
        }
    }
    return OK;
}

/**
 * Module declaration.
 */
module AP_MODULE_DECLARE_DATA replace_module =
{
    STANDARD20_MODULE_STUFF,
    NULL,
    NULL,
    create_replace_server_conf,
    NULL,
    cmds,
    register_hooks
};
