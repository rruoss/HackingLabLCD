# OpenVAS Vulnerability Test
# $Id: embedded_web_server_detect.nasl 50 2013-11-07 18:27:30Z jan $
# Description: Embedded Web Server Detection
#
# Authors:
# Tenable Network Security
#
# Copyright:
# Copyright (C) 2005 TNS
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
tag_summary = "This plugin determines if the remote web server is an embedded service 
(without any user-supplied CGIs) or not";

if(description)
{
 script_id(19689);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 50 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-07 19:27:30 +0100 (Do, 07. Nov 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "Embedded Web Server Detection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "This scripts detects wether the remote host is an embedded web server";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 TNS");
 
 script_family("Web Servers");
 script_dependencies("ciscoworks_detect.nasl", "clearswift_mimesweeper_smtp_detect.nasl",
                     "imss_detect.nasl", "interspect_detect.nasl", "intrushield_console_detect.nasl",
                     "iwss_detect.nasl", "linuxconf_detect.nasl", "securenet_provider_detect.nasl",
                     "tmcm_detect.nasl", "websense_detect.nasl", "xedus_detect.nasl", "compaq_wbem_detect.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");


port = get_kb_item("Services/www");
if ( ! port ) exit(0);

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

banner = get_http_banner(port:port);
if ( ! banner ) exit(0);

if (egrep(pattern:"^[Ss]erver: (CUPS|MiniServ|AppleShareIP|Embedded Web Server|Embedded HTTPD|IP_SHARER|Ipswitch-IMail|MACOS_Personal_Websharing|NetCache appliance|ZyXEL-RomPager|cisco-IOS|u-Server|eMule|Allegro-Software-RomPager|RomPager|Desktop On-Call|D-Link|4D_WebStar|IPC@CHIP|Citrix Web PN Server|SonicWALL|Micro-Web|gSOAP|CompaqHTTPServer/|BBC [0-9.]+; .*[cC]oda)", string:banner) ||
    port == 901 || egrep(pattern: "^Webserver:$", string: banner) )
 	{
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	}

