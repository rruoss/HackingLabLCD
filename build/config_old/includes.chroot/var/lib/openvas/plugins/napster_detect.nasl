# OpenVAS Vulnerability Test
# $Id: napster_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Detect the presence of Napster
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Modifications by rd :
#	- comment slightly changed
#	- added a solution
#	- risk gravity : medium -> low
#	- script_id
#
# Copyright:
# Copyright (C) 2000 by Noam Rathaus <noamr@securiteam.com>, Beyond Security Ltd.
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
tag_summary = "Napster is running on a remote computer. 
Napster is used to share MP3 across the network, and can 
be misused (by modifying the three first bytes of a target 
file) to transfer any file off a remote site.";

tag_solution = "filter this port if you do not want your network
           users to exchange MP3 files or if you fear
	   that Napster may be used to transfer any non-mp3 file";

if(description)
{
 script_id(10344);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "Detect the presence of Napster";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Detect the presence of Napster";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 Beyond Security");
 family = "Peer-To-Peer File Sharing";
 script_family(family);

 script_require_ports("Services/napster", 6699);
 script_dependencies("find_service.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("misc_func.inc");

 uk = 0;
 port = get_kb_item("Services/napster");
 if (!port) {
 	port = 6699;
	uk = 1;
	}
 if (get_port_state(port))
 {
  soctcp6699 = open_sock_tcp(port);
  if (soctcp6699)
  {
   resultrecv = recv(socket:soctcp6699, length:50);
   if ("1" >< resultrecv)
   {
    data = string("GET\r\n");
    resultsend = send(socket:soctcp6699, data:data);
    resultrecv = recv(socket:soctcp6699, length:50);
    if (!resultrecv)
    {
     data = string("GET /\r\n");
     resultsend = send(socket:soctcp6699, data:data);
     resultrecv = recv(socket:soctcp6699, length:150);

     if ("FILE NOT SHARED" >< resultrecv)
     {
      security_warning(port:port);
      if(uk)register_service(proto:"napster", port:6699);
     }
    }
   }
   close(soctcp6699);
  }
 }
