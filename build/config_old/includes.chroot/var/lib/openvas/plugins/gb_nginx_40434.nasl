###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_40434.nasl 14 2013-10-27 12:33:37Z jan $
#
# nginx Space String Remote Source Code Disclosure Vulnerability
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
tag_summary = "nginx is prone to a remote source code-disclosure vulnerability
because it fails to properly sanitize user-supplied input.

An attacker can exploit this vulnerability to view the source code
of files in the context of the server process, which may aid in
further attacks.

This issue affects nginx versions prior to 0.8.36.";

tag_solution = "Reportedly, the issue is fixed in version 0.8.36. Please contact the
vendor for more information.";

if (description)
{
 script_id(100658);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-31 18:31:53 +0200 (Mon, 31 May 2010)");
 script_bugtraq_id(40434);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("nginx Space String Remote Source Code Disclosure Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40434");
 script_xref(name : "URL" , value : "http://nginx.org/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed nginx version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","nginx_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("nginx/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:8000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner || "Server: nginx" >!< banner)exit(0);

version = eregmatch(pattern:"Server: nginx/([0-9.]+)" , string:banner);
if(isnull(version[1]))exit(0);

if(version_is_less(version: version[1], test_version:"0.8.36")) {

  security_warning(port:port);
  exit(0); 

}  


exit(0);

