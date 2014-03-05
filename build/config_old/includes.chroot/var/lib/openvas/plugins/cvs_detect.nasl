# OpenVAS Vulnerability Test
# $Id: cvs_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: A CVS pserver is running
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
tag_summary = "A CVS (Concurrent Versions System) server is installed, and it is configured
to have its own password file, or use that
of the system. This service starts as a daemon, listening on port
TCP:port.
Knowing that a CVS server is present on the system gives attackers
additional information about the system, such as that this is a
UNIX based system, and maybe a starting point for further attacks.";

tag_solution = "Block those ports from outside communication";

if(description)
{
 script_id(10051);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"3.3");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "A CVS pserver is running";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "A CVS pserver is running";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 script_family("Service detection");
 script_require_ports("Services/cvspserver", port);
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
port = get_kb_item("Services/cvspserver");
if(!port)port = 2401;

if(get_port_state(port))
{
 soc = open_sock_tcp(port);

 if (soc)
 {
  senddata = string("\r\n\r\n");
  send(socket:soc, data:senddata);

  recvdata = recv_line(socket:soc, length:1000);
  if ("cvs" >< recvdata)
  {
    security_note(port);
  }
  close(soc);
 }
}
