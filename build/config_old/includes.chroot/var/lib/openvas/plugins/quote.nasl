# OpenVAS Vulnerability Test
# $Id: quote.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Quote of the day
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
tag_solution = "- Under Unix systems, comment out the 'qotd' line in /etc/inetd.conf
  and restart the inetd process

- Under Windows systems, set the following registry keys to 0 :
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableTcpQotd
  HKLM\System\CurrentControlSet\Services\SimpTCP\Parameters\EnableUdpQotd
   
Then launch cmd.exe and type :

   net stop simptcp
   net start simptcp
   
To restart the service.";

tag_summary = "The quote service (qotd) is running on this host.

Description :

A server listens for TCP connections on TCP port 17. Once a connection 
is established a short message is sent out the connection (and any 
data received is thrown away). The service closes the connection 
after sending the quote.

Another quote of the day service is defined as a datagram based
application on UDP.  A server listens for UDP datagrams on UDP port 17.
When a datagram is received, an answering datagram is sent containing 
a quote (the data in the received datagram is ignored).


An easy attack is 'pingpong' which IP spoofs a packet between two machines
running qotd. This will cause them to spew characters at each other,
slowing the machines down and saturating the network.";


if(description)
{
 script_id(10198);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-1999-0103");
 name = "Quote of the day";
 script_name(name);

    desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 
 script_description(desc);
 

 summary = "Checks for the presence of qotd";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 1999 Mathieu Perrin");

 family = "Useless services";
 script_family(family);
 script_dependencies("find_service.nasl", "find_service2.nasl");

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

if(get_port_state(17))
{
 p = known_service(port:17);
 if(!p || p == "qotd")
 {
 soc = open_sock_tcp(17);
 if(soc)
  {
    a = recv_line(socket:soc, length:1024);
    if(a)security_warning(17);
    close(soc);
  }
 }
}

if(get_udp_port_state(17))
{		  
 udpsoc = open_sock_udp(17);
 send(socket:udpsoc, data:'\r\n');
 b = recv(socket:udpsoc, length:1024);
 if(b)security_warning(port:17, protocol:"udp");
 close(udpsoc);
}
