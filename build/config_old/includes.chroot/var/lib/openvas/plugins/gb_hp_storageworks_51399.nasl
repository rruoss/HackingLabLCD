###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_storageworks_51399.nasl 12 2013-10-27 11:15:33Z jan $
#
# HP StorageWorks Default Accounts and Directory Traversal Vulnerabilities
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
tag_summary = "HP StorageWorks is prone to a security-bypass vulnerability and a directory-
traversal vulnerability.

An attacker could exploit these issues to access arbitrary files on
the affected computer, or gain administrative access to the
affected application. This may aid in the compromise of the
underlying computer.

HP StorageWorks P2000 G3 is affected.";

tag_solution = "The vendor released an update to address this issue. Please see the
references for more information.";

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if (description)
{
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51399");
 script_xref(name : "URL" , value : "http://h10010.www1.hp.com/wwpc/us/en/sm/WF05a/12169-304616-241493-241493-241493-3971478.html");
 script_xref(name : "URL" , value : "http://www.compaq.com/storage/");
 script_xref(name : "URL" , value : "http://www.zerodayinitiative.com/advisories/ZDI-12-015/");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/885499");
 script_id(103431);
 script_bugtraq_id(51399);
 script_cve_id("CVE-2011-4788","CVE-2012-0697");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_version ("$Revision: 12 $");

 script_name("HP StorageWorks Default Accounts and Directory Traversal Vulnerabilities");

 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2012-02-21 13:19:06 +0100 (Tue, 21 Feb 2012)");
 script_description(desc);
 script_summary("Determine if it is possible to login with default credentials");
 script_category(ACT_ATTACK);
 script_family("Default Accounts");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl","ssh_detect.nasl","telnetserver_detect_type_nd_version.nasl");
 script_require_ports("Services/www", 80, "Services/ssh", 22, "Services/telnet", 23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ssh_func.inc");
include("telnet_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port:port);
if("WindRiver-WebServer" >!< banner)exit(0);

buf = http_get_cache(item:"/", port:port);

if("<title>HP StorageWorks" >< buf) {

  credentials = make_array('monitor', '!monitor','manage', '!manage','ftp', '!ftp');

  # ssh
  port = get_kb_item("Services/ssh");
  if(!port ) port = 22;
  if(get_port_state(port)) {

  foreach credential (keys(credentials)) {

     if(!soc = open_sock_tcp(port))break;

       user = credential;
       pass = credentials[credential];

       login = ssh_login (socket:soc, login:user, password:pass, pub:NULL, priv:NULL, passphrase:NULL);

       if(login == 0) {
   
         desc = desc + '\n\nIt was possible to login via ssh using "' + user + '" as username and "' + pass + '" as password.\n';  
         security_hole(port:port,data:desc);
         close(soc);
         exit(0);

       }

       close(soc);

    }  

  }

  # telnet
  port = get_kb_item("Services/telnet");
  if(!port) port = 23;

  if(get_port_state(port)) {

    foreach credential (keys(credentials)) {
   
      if(!soc = open_sock_tcp(port))break;

      user = credential;
      pass = credentials[credential];

      b = telnet_negotiate(socket:soc);

      if("Login" >!< b)break;

      send(socket:soc,data:string(user,"\r\n"));
      answer = recv(socket:soc, length:4096);

      send(socket:soc, data:string(pass,"\r\n"));
      answer = recv(socket:soc, length:4096);

      if("StorageWorks" >< answer && "System Name" >< answer) {

        desc = desc + '\n\nIt was possible to login via telnet using "' + user + '" as username and "' + pass + '" as password.\n';
        security_hole(port:port,data:desc);
        close(soc);
        exit(0);

      }  

      close(soc);

    }  
  }  

  exit(99);

}  

exit(0);
