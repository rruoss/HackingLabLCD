# OpenVAS Vulnerability Test
# $Id: global_settings.nasl 50 2013-11-07 18:27:30Z jan $
# Description: Global variable settings
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2004 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_summary = "This plugin configures miscellaneous global variables 
for OpenVAS scripts. It does not perform any security check
but may disable or change the behaviour of others.";

if(description)
{
 script_id(12288);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 50 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-07 19:27:30 +0100 (Do, 07. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 name = "Global variable settings";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);
 
 summary = "Global variable settings";
 script_summary(summary);
 
 script_category(ACT_SETTINGS);	
 
 script_copyright("This script is Copyright (C) 2004 Michel Arboi");
 family = "Settings";
 script_family(family);
 
 script_add_preference(name:"Enable CGI scanning", type:"checkbox", value:"yes");
 script_add_preference(name:"Network type", type:"radio", value:"Mixed (use RFC 1918);Private LAN; Public WAN (Internet)");
 script_add_preference(name:"Enable experimental scripts", type:"checkbox", value:"no");
 script_add_preference(name:"Thorough tests (slow)", type:"checkbox", value:"no");
 script_add_preference(name:"Report verbosity", type:"radio", value:"Normal;Quiet;Verbose");
 script_add_preference(name:"Report paranoia", type:"radio", value:"Normal;Avoid false alarms;Paranoid (more false alarms)");
 script_add_preference(name:"Log verbosity", type:"radio", value:"Normal;Quiet;Verbose;Debug");
 script_add_preference(name:"Debug level", type:"entry", value:"0");
 script_add_preference(name:"HTTP User-Agent", type:"entry", value: "");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

opt = script_get_preference("Enable CGI scanning");
if ( opt == "no" ) set_kb_item(name:"Settings/disable_cgi_scanning", value:TRUE);

opt = script_get_preference("Enable experimental scripts");
if (! opt) opt = "no";
set_kb_item(name:"global_settings/experimental_scripts", value:opt);
if ( opt == "yes" ) set_kb_item(name:"Settings/ExperimentalScripts", value:TRUE);

opt = script_get_preference("Thorough tests (slow)");
if (! opt) opt = "no";
set_kb_item(name:"global_settings/thorough_tests", value:opt);

if ( opt == "yes" ) set_kb_item(name:"Settings/ThoroughTests", value:TRUE);

opt = script_get_preference("Report verbosity");
if (! opt) opt = "Normal";
set_kb_item(name:"global_settings/report_verbosity", value:opt);

opt = script_get_preference("Log verbosity");
if (! opt) opt = "Quiet";
set_kb_item(name:"global_settings/log_verbosity", value:opt);

opt = script_get_preference("Debug level");
if (! opt) opt = "0";
set_kb_item(name:"global_settings/debug_level", value:int(opt));

opt = script_get_preference("Report paranoia");
if (! opt) opt = "Normal";
set_kb_item(name:"global_settings/report_paranoia", value:opt);

opt = script_get_preference("Network type");
if (! opt) opt = "Mixed (RFC 1918)";
set_kb_item(name:"global_settings/network_type", value:opt);

opt = script_get_preference("HTTP User-Agent");
if (! opt) opt = "Mozilla/5.0 (X11; Linux; rv:17.0) Gecko/17.0 Firefox/17.0 OpenVAS/" + OPENVAS_VERSION;
set_kb_item(name:"global_settings/http_user_agent", value:opt);
set_kb_item(name:"http/user-agent", value:opt);
