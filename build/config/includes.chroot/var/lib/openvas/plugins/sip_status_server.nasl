# OpenVAS Vulnerability Test
# $Id: sip_status_server.nasl 17 2013-10-27 14:01:43Z jan $
# Description: sxdesign SIPd Status Server Detection
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
tag_summary = "A SIP status server is running on this port.

An attacker may use the remote status information of this server to
collect sensitive information such as server version, emails, 
and ip addresses (internal and external).";

tag_solution = "Access to this port should be restricted to trusted users only";

if(description)
{
 script_id(11945);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 name = "sxdesign SIPd Status Server Detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 summary = "SIP Status Server Detection";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
 family = "Service detection";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 6050);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:6050);
if(!port)exit(0);

res = http_get_cache(item:"/", port:port);
if ( res == NULL ) exit(0);
if ("SIP Server Status" >< res && "Server Version" >< res) security_note(port);
