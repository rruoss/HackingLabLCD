###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_up_time_47599.nasl 13 2013-10-27 12:16:33Z jan $
#
# up.time Software Administration Interface Remote Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_summary = "up.time software is prone to a remote authentication-bypass
vulnerability.

Attackers can exploit this issue to bypass authentication and perform
unauthorized actions.

up.time 5 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(103148);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)");
 script_bugtraq_id(47599);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_name("up.time Software Administration Interface Remote Authentication Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47599");
 script_xref(name : "URL" , value : "http://www.insomniasec.com/advisories/ISVA-110427.2.htm");
 script_xref(name : "URL" , value : "http://www.uptimesoftware.com/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if up.time software is prone to a remote authentication-bypass vulnerability.");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_up_time_detect.nasl");
 script_require_ports("Services/www", 9999);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:9999);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port, app:"up.time"))exit(0);
url = string(dir,"/index.php?userid=admin&firstTimeLogin=True&password=&confirmPassword=&adminEmail=admin@admin&monitorEmail=admin@admin"); 

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )exit(0);

if("The password cannot be blank" >< buf) {
  security_warning(port:port);
  exit(0);
}  

exit(0);
