###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharp_mx_m850_default_administrator_password.nasl 11 2013-10-27 10:12:02Z jan $
#
# Sharp MX-M850 Default Administrator Password
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
tag_summary = "The remote Sharp MX-M850 has the default password 'admin'.";


tag_solution = "Change the password.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103667";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Sharp MX-M850 Default Administrator Password");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://sharp-world.com/");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-02-22 12:01:48 +0100 (Fri, 22 Feb 2013)");
 script_description(desc);
 script_summary("Determine if the remote Sharp MX-M850 has a default password");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);

host = get_host_name();

banner = get_http_banner(port:port);
if("Server: Rapid Logic/1.1" >!< banner)exit(0);

url = '/login.html';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("Set-Cookie" >!< buf)exit(0);
cookie = eregmatch(pattern:string("Set-Cookie: ([^\r\n ]+)"), string:buf);
if(isnull(cookie[1]))exit(0);

req = string("POST /login.html?/main.html HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "DNT: 1\r\n",
             "Connection: close\r\n",
             "Referer: http://",host,"/login.html?/main.html\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Cookie: ",cookie[1],"\r\n",
             "Content-Length: 68\r\n",
             "\r\n",
             "ggt_textbox%2810006%29=admin&action=loginbtn&ggt_hidden%2810008%29=3");

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("Set-Cookie" >!< result)exit(0);
cookie = eregmatch(pattern:string("Set-Cookie: ([^\r\n ]+)"), string:result);
if(isnull(cookie[1]))exit(0);

req = string("GET /security_password.html HTTP/1.1\r\n",
             "Host: ",host,"\r\n",
             "Cookie: ", cookie[1],"\r\n\r\n");

send(socket:soc, data:req);
while(buf = recv(socket:soc, length:1024)) {
  result += buf;
}  

close(soc);

if("User Name: Administrator" >< result && "Logout(L)" >< result) {

  security_hole(port:port);
  exit(0);

}

exit(0);
