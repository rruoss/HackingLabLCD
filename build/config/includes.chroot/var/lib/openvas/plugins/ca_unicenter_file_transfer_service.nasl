# OpenVAS Vulnerability Test
# $Id: ca_unicenter_file_transfer_service.nasl 17 2013-10-27 14:01:43Z jan $
# Description: CA Unicenter's File Transfer Service is running
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
tag_summary = "CA Unicenter's File Transfer Service uses ports TCP:3104, UDP:4104 and
TCP:4105 for communication between its clients and other CA Unicenter
servers. These ports are open, meaning that CA Unicenter File Transfer
service is probably running, and is open for outside attacks.";

tag_solution = "Block those ports from outside communication";

if(description)
{
 script_id(10032);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "CA Unicenter's File Transfer Service is running";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "CA Unicenter's File Transfer Service is running";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "Windows";
 script_family(family);
 script_require_ports(3104, 4105);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

 if ((get_port_state(3104)) && (get_port_state(4105)) && (get_udp_port_state(4104)))
 {
  soctcp    = open_sock_tcp(3104);
  if(!soctcp)exit(0);
  else close(soctcp);
 
  soctcp     = open_sock_tcp(4105);
  if(!soctcp)exit(0);
  else close(soctcp);


  socudp4104 = open_sock_udp(4104);

  if (socudp4104)
  {
   send (socket:socudp4104, data:string("\r\n"));
   result = recv(socket:socudp4104, length:1000);
   if (strlen(result)>0)
   {
    #set_kb_item(name:"Windows compatible", value:TRUE);
    security_warning(port:4104, protocol:"udp");
   }

  close(socudp4104);
 }
}
