/*#############################################
#
# Title:        mod_but_config.c
# Author:       e1@but.ch
# Date:         November 21, 2006
# Version:      2.9
#
#############################################*/
/* $Id: mod_but_config.c 65 2008-05-30 17:05:05Z droethli $ */

#include "mod_but.h"

/*
 * Most if not all of these methods should be replaced by the standard
 * APR configuration stubs.
 */

const char *
mod_but_enabled_on(cmd_parms *cmd, void *dummy, int arg)
{
	/*
	 * Here, we defined the configuration defaults if the user does
	 * not set MOD_BUT_* directives in httpd.conf
	 * See the mod_but.h for the default values
	 */
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	conf->enabled = arg;
	conf->client_refuses_cookies_url = MOD_BUT_COOKIE_REFUSE_URL;
	conf->cookie_name = MOD_BUT_COOKIE_NAME;
	conf->cookie_domain = MOD_BUT_COOKIE_DOMAIN;
	conf->cookie_path = MOD_BUT_COOKIE_PATH;
	conf->cookie_expiration = MOD_BUT_COOKIE_EXPIRATION;
	conf->cookie_secure = MOD_BUT_COOKIE_SECURE;
	conf->cookie_httponly = MOD_BUT_COOKIE_HTTPONLY;
	conf->session_free_url = MOD_BUT_SESSION_FREE_URL;
	conf->session_timeout = MOD_BUT_SESSION_TIMEOUT;
	conf->session_hacking_attempt_url = MOD_BUT_SESSION_ATTEMPT_URL;
	conf->session_inactivity_timeout = MOD_BUT_SESSION_INACTIVITY_TIMEOUT;
	conf->session_inactivity_timeout_url = MOD_BUT_SESSION_INACTIVITY_TIMEOUT_URL;
	conf->session_expired_url = MOD_BUT_SESSION_TIMEOUT_URL;
	conf->session_timeout_history = MOD_BUT_SESSION_TIMEOUT_HISTORY;
	conf->session_destroy = MOD_BUT_SESSION_DESTROY;
	conf->session_destroy_url = MOD_BUT_SESSION_DESTROY_URL;
	conf->session_renew_url = MOD_BUT_SESSION_RENEW_URL;
	conf->authorization_enabled = 0;
	conf->global_logon_server_url = MOD_BUT_LOGON_SERVER_URL;
	conf->global_logon_server_url_1 = MOD_BUT_LOGON_SERVER_URL_1;
	conf->global_logon_server_url_2 = MOD_BUT_LOGON_SERVER_URL_2;
	conf->global_logon_auth_cookie_name = MOD_BUT_LOGON_AUTH_COOKIE_NAME;
	conf->global_logon_auth_cookie_value = MOD_BUT_LOGON_AUTH_COOKIE_VALUE;
	conf->all_shm_space_used_url = MOD_BUT_SHM_USED_URL;
	conf->session_store_free_cookies = MOD_BUT_FREE_COOKIES;
	conf->service_list_cookie_name = MOD_BUT_SERVICE_LIST_COOKIE_NAME;
	conf->service_list_cookie_value = MOD_BUT_SERVICE_LIST_COOKIE_VALUE;
	conf->service_list_error_url = MOD_BUT_SERVICE_LIST_ERROR_URL;
	conf->authorized_logon_url = MOD_BUT_AUTHORIZED_LOGON_URL;
	return OK;
}

const char *mod_but_client_refuses_cookies(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->client_refuses_cookies_url = arg;
	}
	return OK;
}

const char *mod_but_set_cookie_name(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->cookie_name = arg;
	}
	return OK;
}

const char *mod_but_set_cookie_domain(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->cookie_domain = arg;
	}
	return OK;
}

const char *mod_but_set_cookie_path(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->cookie_path = arg;
	}
	return OK;
}

const char *mod_but_set_cookie_expiration(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->cookie_expiration = arg;
	}
	return OK;
}

const char *mod_but_set_cookie_secure(cmd_parms *cmd, void *dummy, int arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	conf->cookie_secure = arg;
	return OK;
}

const char *mod_but_set_cookie_httponly(cmd_parms *cmd, void *dummy, int arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	conf->cookie_httponly = arg;
	return OK;
}

const char *mod_but_set_session_free_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_free_url = arg;
	}
	return OK;
}

const char *mod_but_set_session_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_timeout = apr_atoi64(arg);
	}
	return OK;
}

const char *mod_but_set_session_hacking_attempt_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_hacking_attempt_url = arg;
	}
	return OK;
}

const char *mod_but_set_session_inactivity_timeout(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_inactivity_timeout = apr_atoi64(arg);
	}
	return OK;
}

const char *mod_but_set_session_inactivity_timeout_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_inactivity_timeout_url = arg;
	}
	return OK;
}

const char *mod_but_set_session_expired_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_expired_url = arg;
	}
	return OK;
}

const char *mod_but_set_session_renew_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_renew_url = arg;
	}
	return OK;
}

const char *mod_but_set_all_shm_used_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->all_shm_space_used_url = arg;
	}
	return OK;
}

const char *mod_but_set_session_timeout_history(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_timeout_history = apr_atoi64(arg);
	}
	return OK;
}

const char *mod_but_set_session_destroy(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_destroy = arg;
	}
	return OK;
}

const char *mod_but_set_session_destroy_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_destroy_url = arg;
	}
	return OK;
}

const char *mod_but_authorization_enabled_on(cmd_parms *cmd, void *dummy, int arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	conf->authorization_enabled = arg;
	return OK;
}

const char *mod_but_global_logon_server_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->global_logon_server_url = arg;
	}
	return OK;
}

const char *mod_but_global_logon_server_url_1(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->global_logon_server_url_1 = arg;
	}
	return OK;
}

const char *mod_but_global_logon_server_url_2(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->global_logon_server_url_2 = arg;
	}
	return OK;
}

const char *mod_but_global_logon_auth_cookie_name(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->global_logon_auth_cookie_name = arg;
	}
	return OK;
}

const char *mod_but_global_logon_auth_cookie_value(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->global_logon_auth_cookie_value = arg;
	}
	return OK;
}

const char *mod_but_set_session_store_free_cookies(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->session_store_free_cookies = arg;
	}
	return OK;
}

const char *mod_but_set_service_list_cookie_name(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->service_list_cookie_name = arg;
	}
	return OK;
}

const char *mod_but_set_service_list_cookie_value(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->service_list_cookie_value = arg;
	}
	return OK;
}

const char *mod_but_set_service_list_error_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->service_list_error_url = arg;
	}
	return OK;
}

const char *mod_but_service_list_enabled_on(cmd_parms *cmd, void *dummy, int arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->service_list_enabled_on = arg;
	}
	return OK;
}

const char *mod_but_set_authorized_logon_url(cmd_parms *cmd, void *dummy, const char *arg)
{
	mod_but_server_t *conf = ap_get_module_config(cmd->server->module_config, &but_module);
	if (arg) {
		conf->authorized_logon_url = arg;
	}
	return OK;
}

