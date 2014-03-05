# OpenVAS Vulnerability Test
# $Id: ca_unicenter_transport_service.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CA Unicenter's Transport Service is running
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 1999 SecuriTeam
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
tag_summary = "CA Unicenter Transport Service uses ports TCP:7001, TCP:7003 and UDP:7004
for communication between its clients and other CA Unicenter servers. Since
the above ports are open, CA Unicenter's Transport service is probably
running, and is open for outside attacks.";

tag_solution = "Block those ports from outside communication";

if(description)
{
 script_id(10033);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"3.3");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "CA Unicenter's Transport Service is running";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "CA Unicenter's Transport Service is running";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "Windows";
 script_family(family);
 script_require_ports(7001, 7003);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

if ((get_port_state(7001)) && (get_port_state(7003)) && (get_udp_port_state(7004)))
{
 soctcp7001 = open_sock_tcp(7001);
 soctcp7003 = open_sock_tcp(7003);
 socudp7004 = open_sock_udp(7004);

 if ((soctcp7001) && (soctcp7003) && (socudp7004))
 {
  send (socket:socudp7004, data:"\r\n");
  result = recv(socket:socudp7004, length:1000);
  if (strlen(result)>0)
  {
   #set_kb_item(name:"Windows compatible", value:TRUE);
   security_warning(0);
  }
 }

 if(soctcp7001)close(soctcp7001);
 if(soctcp7003)close(soctcp7003);
 close(socudp7004);
}
