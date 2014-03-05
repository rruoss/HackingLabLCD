###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_seagate_nas_default_admin.nasl 11 2013-10-27 10:12:02Z jan $
#
# Seagate NAS Default Login
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
tag_impact = "
Impact Level: Application";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103754";
CPE = "cpe:/h:seagate:blackarmor_nas";

tag_summary = 'The remote Seagate NAS is prone to a default account
authentication bypass vulnerability.';

tag_impact = 'This issue may be exploited by a remote attacker to gain
access to sensitive information or modify system configuration.';

tag_insight = 'It was possible to login with username "admin" and password "admin".';
tag_vuldetect = 'Try to login with admin/admin';
tag_solution = 'Change the password.';

if (description)
{
 script_oid(SCRIPT_OID); 
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Seagate NAS Default Login");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Solution:
" + tag_solution;

 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-08-08 14:02:06 +0200 (Thu, 08 Aug 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to login as admin/admin");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_seagate_blackarmor_nas_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("seagate_nas/installed");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "impact" , value : tag_impact);
   script_tag(name : "vuldetect" , value : tag_vuldetect);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "solution" , value : tag_solution);
 }

 exit(0);
}

include("http_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
#port = 80;

url = "/index.php";
req = http_get(item:url, port:port);
buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

if("<title>Seagate NAS" >!< buf || "Set-Cookie" >!< buf)exit(0);

co = eregmatch(pattern:'Set-Cookie: ([^\n\r]+)', string:buf);
if(isnull(co[1]))exit(0);

cookie = co[1];

host = get_host_name();

data = 'p_user=admin&p_pass=admin&lang=en&xx=1&loginnow=Login';
len = strlen(data);

req = 'POST / HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' + 
      'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS\r\n' + 
      'Referer: http://' + host + '/?lang=en\r\n' + 
      'DNT: 1\r\n' + 
      'Cookie: ' + cookie + '\r\n' + 
      'Content-Type: application/x-www-form-urlencoded\r\n' + 
      'Content-Length: ' + len + '\r\n' + 
      '\r\n' + data;

result = http_send_recv(port:port, data:req, bodyonly:FALSE);      

req = 'GET /admin/system_status.php?lang=en&gi=sy002 HTTP/1.1\r\n' + 
      'Host: ' + host + '\r\n' +
      'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS\r\n' +
      'Referer: http://' + host + '/?lang=en\r\n' +
      'DNT: 1\r\n' +
      'Cookie: ' + cookie + '\r\n' + '\r\n';

buf = http_send_recv(port:port, data:req, bodyonly:TRUE);      

if(">Logout<" >< buf && ">System Status<" >< buf && "Admin Password" >< buf) {

  security_hole(port:port);
  exit(0);

}  

exit(0);

