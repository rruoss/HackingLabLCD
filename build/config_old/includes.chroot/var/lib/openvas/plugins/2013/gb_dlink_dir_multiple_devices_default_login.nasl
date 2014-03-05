###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_multiple_devices_default_login.nasl 11 2013-10-27 10:12:02Z jan $
#
# Dlink DIR Multiple Devices Default Login
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
tag_summary = "The remote Dlink DIR device is prone to a default account
authentication bypass vulnerability. This issue may be exploited
by a remote attacker to gain access to sensitive information or
modify system configuration without requiring authentication.";


tag_solution = "Change the password.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103690";  

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
 script_tag(name:"creation_date", value:"2013-04-09 11:03:03 +0100 (Tue, 09 Apr 2013)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_name("Dlink DIR Multiple Devices Default Login");
 script_description(desc);
 script_summary("Try to login with default credentials");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_dlink_dir_detect.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("host_is_dlink_dir");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");

port = get_kb_item("dlink_dir_port");
if(!port)exit(0);

if(!get_port_state(port))exit(0);

host = get_host_name();

username ="admin";

passwords = make_list("","admin","Admin","password","12345","pass","year2000","private","public");

foreach pass (passwords) {

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  login = "REPORT_METHOD=xml&ACTION=login_plaintext&USER=" + username + "&PASSWD=" + pass + "&CAPTCHA="; 
  len = strlen(login);

  req = string("POST /session.cgi HTTP/1.1\r\n",
               "Host: ", host, ":", port,"\r\n",
               "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 OpenVAS/17.0\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
               "Accept-Encoding: identity\r\n",
               "DNT: 1\r\n",
               "Connection: keep-alive\r\n",
               "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
               "Referer: http://",host,":",port,"/setup.php\r\n",
               "Content-Length: 68\r\n",
               "Cookie: uid=g0C06BeyB7\r\n",
               "\r\n",
               login);

  send(socket:soc, data:req);

  recv = recv(socket:soc, length:512);
  close(soc);

  if(recv =~ "HTTP/1.. (404|500)") exit(0);

  if("<RESULT>SUCCESS</RESULT>" >< recv) {

    if(strlen(pass) > 0)
      message = desc + '\n\nIt was possible to login with username "admin" and password "' + pass + '".\n';
    else
      message = desc + '\n\nIt was possible to login with username "admin" and an empty password\n';

    security_hole(port:port, data:message);
    exit(0);

  }
}

exit(99);
