# OpenVAS Vulnerability Test
# $Id: healthd_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: HealthD detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com> 
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Should cover BID: 1107
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com> 
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "The FreeBSD Health Daemon was detected.
The HealthD provides remote administrators with information about the 
current hardware temperature, fan speed, etc, allowing them to monitor
the status of the server.

Such information about the hardware's current state might be sensitive; 
it is recommended that you do not allow access to this service from the 
network.";

tag_solution = "Configure your firewall to block access to this port.";

if(description)
{
 script_id(10731); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"3.3");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "HealthD detection";
 script_name(name);
 
desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "HealthD detection";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_family( "Service detection");

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/healthd", 1281, 9669);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

l = get_kb_list("Services/healthd");
if ( isnull(l) ) l = make_list();
port_l = make_list(1281, 9669, l);
foreach port (port_l)
 if (port && get_port_state(port))
 {
  soctcphealthd = open_sock_tcp(port);

  if (soctcphealthd)
  {
   data = string("foobar");
   resultsend = send(socket:soctcphealthd, data:data);
   resultrecv = recv(socket:soctcphealthd, length:8192);
   if ("ERROR: Unsupported command" >< resultrecv)
   {
    data = string("VER d");
    resultsend = send(socket:soctcphealthd, data:data);
    resultrecv = recv(socket:soctcphealthd, length:8192);

    if ("ERROR: Unsupported command" >< resultrecv)
    {
     security_warning(port:port);
    }
    else
    {
data = string("The FreeBSD Health Daemon was detected.\n",
"The HealthD provides remote administrators with information about\n",
"the current hardware temperature, fan speed, etc, allowing them to monitor\n",
"the status of the server.\n",
"\n",
"Such information about the hardware's current state might be sensitive; \n",
"it is recommended that you do not allow access to this service from the \n",
"network.",
"\n\nThe HealthD version we found is: ", resultrecv, "\n\n",
"Solution: Configure your firewall to block access to this port.\n",
"\n");
     security_warning(port:port, data:data);
    }
   close(soctcphealthd);
   }
  }
 }
