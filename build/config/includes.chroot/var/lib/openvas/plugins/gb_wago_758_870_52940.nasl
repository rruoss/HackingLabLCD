###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wago_758_870_52940.nasl 12 2013-10-27 11:15:33Z jan $
#
# WAGO I/O SYSTEM 758 Series Insecure Credential Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Gaspar Modelo-Howard <gmhoward@gmail.com>
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
tag_summary = "The WAGO IPC 758 series are prone to a security-bypass vulnerability
caused by a set of hard-coded passwords.

Successful attacks can allow a remote attacker to gain unauthorized
access to the vulnerable device, using the HTTP or TELNET service.";


desc = "
 Summary:
 " + tag_summary;


if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52940");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52942");
 script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-3013");
 script_xref(name : "URL" , value : "http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-4879");
 script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICSA-12-249-02.pdf");
 script_xref(name : "URL" , value : "http://www.us-cert.gov/control_systems/pdf/ICS-ALERT-12-097-01.pdf");
 script_xref(name : "URL" , value : "http://www.wago.com/wagoweb/documentation/app_note/a1176/a117600e.pdf");
 script_id(103465);
 script_bugtraq_id(52940,52942);
 script_cve_id("CVE-2012-4879","CVE-2012-3013");
 script_version ("$Revision: 12 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C"); 
 script_name("WAGO I/O SYSTEM 758 Series Insecure Credential Vulnerabilities");
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-04-12 11:29:33 +0200 (Thu, 12 Apr 2012)"); 
 script_description(desc);
 script_summary("Determine if it is possible to login into the remote wago");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80, "Services/telnet", 23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("telnet_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

credentials = make_list("root:admin","admin:admin","user:user","user:user00","guest:guest");

http_port = get_kb_item("Services/www");
telnet_port = get_kb_item("Services/telnet");

if(!http_port && !telnet_port)exit(0);

url = '/cgi-bin/ssi.cgi/title.ssi';
req = http_get(item:url, port:http_port);
buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

if("Wago IO-IPC" >< buf) {

  url = '/security.htm';
  req = http_get(item:url, port:http_port);
  buf = http_keepalive_send_recv(port:http_port, data:req, bodyonly:FALSE);

  if("Unauthorized" >< buf) {

    foreach credential (credentials) { 

       userpass64 = base64(str:credential);
       
       req = string("GET ", url," HTTP/1.1\r\n",
               "Host: ", get_host_name(),"\r\n",
               "Authorization: Basic ",userpass64,"\r\n",
               "\r\n");

       resp = http_keepalive_send_recv(port:http_port, data:req);

       if("<title>Configuration side for the web security" >< resp && "Webserver security functions" >< resp) {
         httpdesc = desc + '\n\nIt was possible to login using the following credentials:\nUsername:Password\n' + credential + '\n';
         security_hole(port:http_port,data:httpdesc);
         break;
       }


    }  

  } else {
    desc = desc + '\n\nThe Wago Web Configuration Page is not protected by any credentials\n';
    security_hole(port:http_port,data:desc);
  } 

}  

soc = open_sock_tcp(telnet_port);
if(!soc)exit(0);

r = telnet_negotiate(socket:soc);
if("WagoIPC1 login" >< r) {

  foreach credential (credentials) {

    cred = split(credential, sep:":", keep:FALSE);
    user = cred[0];
    pass = cred[1];

    send(socket:soc, data:user + '\n');
    recv = recv(socket:soc, length:512);

    if("Password" >!< recv)continue;

    send(socket:soc, data:pass + '\n');
    recv = recv(socket:soc, length:512);

    if("-sh" >!< recv)continue;

    desc1 = desc + '\n\nIt was possible to login using the following credentials:\nUsername:Password\n' + credential + '\n';
    security_hole(port:telnet_port,data:desc1);

    send(socket:soc, data:'su\n');
    recv = recv(socket:soc, length:512);

    if("Password" >!< recv)continue;

    send(socket:soc, data:'ko2003wa\n');
    recv = recv(socket:soc, length:512);

    close(soc);

    if("this is the super user account" >< recv) {
      desc2 = desc + '\n\nAfter it was possible to login using default credentials it was\nalso possible to "su" to the super user account using "ko2003wa" as password\n';
      security_hole(port:telnet_port,data:desc2);
    }

  }

}

exit(0);
