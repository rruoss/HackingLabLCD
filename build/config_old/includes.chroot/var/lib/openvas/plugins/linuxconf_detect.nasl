# OpenVAS Vulnerability Test
# $Id: linuxconf_detect.nasl 57 2013-11-11 18:12:18Z jan $
# Description: LinuxConf grants network access
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modified by Renaud Deraison <deraison@cvs.nessus.org> :
#	- report modified
#	- removed the warning saying the linuxconf was running,
#	  due to redundancy with find_service.nasl output
#	- script_dependencies() added
#	- script_require_ports() changed
#
# Copyright:
# Copyright (C) 2000 SecuriTeam
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
tag_summary = "Linuxconf is running (Linuxconf is a sophisticated 
administration tool for Linux) and is granting network
access at least to the host openvasd is running onto.

LinuxConf is suspected to contain various buffer overflows,
so you should not let allow networking access to anyone.";

tag_solution = "Disable Linuxconf access from the network by
using a firewall, if you do not need Linuxconf use the 
Linuxconf utility (command line or XWindows based version) 
to disable it.

See additional information regarding the dangers of 
keeping this port open at :
http://www.securiteam.com/exploits/Linuxconf_contains_remotely_exploitable_buffer_overflow.html";


if(description)
{
 script_id(10135);
 script_version("$Revision: 57 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-11 19:12:18 +0100 (Mo, 11. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2000-0017"); 
 name = "LinuxConf grants network access";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Detect Linuxconf access rights";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/linuxconf", 98);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_kb_item("Services/linuxconf");
if(!port)port = 98;
if (get_port_state(port))
{
 soctcp98 = open_sock_tcp(port);

 if (soctcp98)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp98, data:sendata);
  banner = http_recv(socket:soctcp98);
  http_close_socket(soctcp98);
  
  if ("Server: linuxconf" >< banner)
  {
    resultrecv = strstr(banner, "Server: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "Server: ";
    resultrecv = resultrecv - "\n";
   
    banner = string("Linuxconf version is : ");
    banner = banner + resultrecv;
    security_hole(port);
    security_hole(port:port, data:banner);
  }
 }
}
