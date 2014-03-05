# OpenVAS Vulnerability Test
# $Id: chargen.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Chargen
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 1999 Mathieu Perrin
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

include("revisions-lib.inc");
tag_solution = "- Under Unix systems, comment out the 'chargen' line in /etc/inetd.conf 
  and restart the inetd process

- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpChargen
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpChargen
  
 Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service.";

tag_summary = "The remote host is running a 'chargen' service.

Description :

When contacted, chargen responds with some random characters (something
like all the characters in the alphabet in a row). When contacted via UDP, it 
will respond with a single UDP packet. When contacted via TCP, it will 
continue spewing characters until the client closes the connection. 

The purpose of this service was to mostly to test the TCP/IP protocol
by itself, to make sure that all the packets were arriving at their
destination unaltered. It is unused these days, so it is suggested
you disable it, as an attacker may use it to set up an attack against
this host, or against a third party host using this host as a relay.

An easy attack is 'ping-pong' in which an attacker spoofs a packet between 
two machines running chargen. This will cause them to spew characters at 
each other, slowing the machines down and saturating the network.";


if(description)
{
 script_id(10043);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-1999-0103"); 
 name = "Chargen";
 script_name(name);

    desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 

 summary = "Checks for the presence of chargen";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");

 family = "Useless services";
 script_family(family);
 script_dependencies("find_service.nasl");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}
 
#
# The script code starts here
#

include("misc_func.inc");
include("pingpong.inc");



if(get_port_state(19))
{
 p = known_service(port:19);
 if(!p || p == "chargen")
 {
 soc = open_sock_tcp(19);
 if(soc)
  {
    a = recv(socket:soc, length:255, min:255);
    if(strlen(a) > 255)security_warning(19);
    close(soc);
  }
 }
}

		
if(get_udp_port_state(19))
{		  
 udpsoc = open_sock_udp(19);
 data = string("\r\n");
 send(socket:udpsoc, data:data);
 b = recv(socket:udpsoc, length:1024);
 if(strlen(b) > 255)security_warning(port:19,protocol:"udp");
 
 close(udpsoc);
}
