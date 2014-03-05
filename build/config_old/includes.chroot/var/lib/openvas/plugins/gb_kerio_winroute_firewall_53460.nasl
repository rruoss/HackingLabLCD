###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kerio_winroute_firewall_53460.nasl 12 2013-10-27 11:15:33Z jan $
#
# Kerio WinRoute Firewall Web Server Remote Source Code Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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
tag_summary = "Kerio WinRoute Firewall is prone to a remote source-code-
disclosure vulnerability because it fails to properly sanitize user-
supplied input.

An attacker can exploit this vulnerability to view the source code
of files in the context of the server process; this may aid in
further attacks.

Versions prior to Kerio WinRoute Firewall 6.0.0 are vulnerable.";

tag_solution = "Updates are available. Please see the references for more details.";

if (description)
{
 script_id(103487);
 script_bugtraq_id(53460);
 script_version ("$Revision: 12 $");

 script_name("Kerio WinRoute Firewall Web Server Remote Source Code Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53460");
 script_xref(name : "URL" , value : "http://www.kerio.com");

 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-05-11 13:52:12 +0200 (Fri, 11 May 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to read the source code");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
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
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port); 
if("Server: Kerio WinRoute Firewall" >!< banner)exit(0);

url = '/nonauth/login.php%00.txt'; 

if(http_vuln_check(port:port, url:url,pattern:"require_once",extra_check:make_list("configNonauth","CORE_PATH"))) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);

