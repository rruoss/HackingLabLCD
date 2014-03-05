###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_3com_officeconnect_vpn_firewall_default_login.nasl 11 2013-10-27 10:12:02Z jan $
#
# 3Com OfficeConnect VPN Firewall Default Password Security Bypass Vulnerability
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
tag_summary = "The remote 3Com OfficeConnect VPN Firewall is prone to a default account
authentication bypass vulnerability. This issue may be exploited by a
remote attacker to gain access to sensitive information or modify system
configuration.

It was possible to login as Admin with password 'admin'.";


tag_solution = "Change the password.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103711";
CPE = "cpe:/o:hp:3com_officeconnect_vpn_firewall";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("3Com OfficeConnect VPN Firewall Default Password Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_tag(name:"risk_factor", value:"High");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-05-14 11:24:55 +0200 (Tue, 14 May 2013)");
 script_description(desc);
 script_summary("Determine if it is possible to login with password admin");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("gb_3com_officeconnect_vpn_firewall_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("3com_officeconnect_vpn_firewall/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
host = get_host_name();

req = string("POST /cgi-bin/admin?page=x HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 Firefox/17.0 OpenVAS\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
             "Accept-Encoding: Identity\r\n",
             "DNT: 1\r\n",
             "Connection: close\r\n",
             "Referer: http://",host,"/cgi-bin/admin?page=x\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 34\r\n",
             "\r\n",
             "AdminPassword=admin&next=10&page=x");

result = http_send_recv(port:port, data:req, bodyonly:FALSE);

if(result =~ "HTTP/1.. 200" && "INPUT type=hidden name=tk" >< result) {

  tk_val = eregmatch(pattern:'INPUT type=hidden name=tk value="([^"]+)"', string:result);
  if(isnull(tk_val[1]))exit(0);

  tk = tk_val[1];
  login_data = 'next=10&page=0&tk=' + tk;
  len = strlen(login_data);

  req = string("POST /cgi-bin/admin?page=x HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:17.0) Gecko/17.0 Firefox/17.0 OpenVAS\r\n",
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
             "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
             "Accept-Encoding: Identity\r\n",
             "DNT: 1\r\n",
             "Connection: close\r\n",
             "Referer: http://",host,"/cgi-bin/admin?page=x\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ",len,"\r\n",
             "\r\n",
             login_data); 

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if(result =~ "HTTP/1.. 200" && "/stbar.htm" >< result) {

    url = '/cgi-bin/admin?page=1&tk=' + tk + '&next=10';
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if("<title>administration menu" >< tolower(buf)) {
      security_hole(port:port);
      exit(0);
    }  

  }  
}  
