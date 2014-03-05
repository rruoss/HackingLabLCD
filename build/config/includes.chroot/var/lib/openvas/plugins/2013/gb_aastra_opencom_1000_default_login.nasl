###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aastra_opencom_1000_default_login.nasl 11 2013-10-27 10:12:02Z jan $
#
# Aastra OpenCom 1000 Default Login
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
# of the License, or (at your option) any later version
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
tag_summary = "The remote Aastra OpenCom 1000 is prone to a default account
authentication bypass vulnerability. This issue may be exploited by
a remote attacker to gain access to sensitive information or modify
system configuration without requiring authentication.

It was possible to login as user 'Admin' with password 'Admin'.";


tag_solution = "Change the password.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103684";  
CPE = 'cpe:/h:aastra_telecom:opencom_1000';

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution; 
if (description)
{
 
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-03-20 17:03:03 +0100 (Wed, 20 Mar 2013)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Aastra OpenCom 1000 Default Login");
 script_description(desc);
 script_summary("This NVT tries to login with username Admin and password Admin");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_aastra_opencom_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("aastra_opencom/model");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

model = get_kb_item("aastra_opencom/model");
if(!model || model != "1000")exit(0);

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

url = '/login.html';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

token = eregmatch(pattern:"<INPUT TYPE=hidden NAME='login' VALUE='([^']+)'>", string:buf,icase:TRUE);
if(isnull(token[1]))exit(0);

tk = token[1];

pass = hexstr(MD5("Admin"));
str = tk + pass;
login = hexstr(MD5(str));

post = 'login=' + login + '&user=Admin&password=&ButtonOK=OK';
len = strlen(post);
host = get_host_name();

req = string("POST /summary.html HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS/17.0\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
             "Accept-Encoding: identity\r\n",
             "DNT: 1\r\n",
             "Connection: keep-alive\r\n",
             "Referer: http://",host,"/login.html\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             post);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("?uid=" >!< result || result !~ "HTTP/1\.. 302")exit(99);

uid = eregmatch(pattern:string("uid=([^\r\n]+)"), string:result);
if(isnull(uid[1]))exit(0);

url = '/top-bar.html?uid=' + uid[1];
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("javascript:FunctionLogout()" >< buf) {

  security_hole(port:port);
  exit(0);

}

exit(99);
