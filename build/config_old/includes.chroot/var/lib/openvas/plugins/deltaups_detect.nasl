# OpenVAS Vulnerability Test
# $Id: deltaups_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Delta UPS Daemon Detection
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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
tag_summary = "The Delta UPS Daemon is running on this server.

This UPS (see: http://www.deltaww.com/) provides a daemon that shows 
sensitive information, including:
 OS type and version
 Internal network addresses
 Internal numbers used for pager
 Encrypted password
 Latest event log of the machine";

tag_solution = "Block access to the Delta UPS's daemon on this port";

if(description)
{
 script_id(10876);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Delta UPS Daemon Detection";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Delta UPS Daemon Detection";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2002 SecurITeam");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/deltaups", 2710);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

function check(req)
{
 soc = open_sock_tcp(port);
 if(soc)
 {

  send(socket:soc, data:req);
  buf = recv(socket:soc, length:4096);

  close(soc);

  if (("DeltaUPS" >< buf) || ("NET01" >< buf) || ("STS00" >< buf) || ("ATZ" >< buf) || ("ATDT" >< buf))
  {
        security_warning(port:port);
        return(1);
  }
 }
 return(0);
}

port = get_kb_item("Services/deltaups");
if(!port)port = 2710;
cginameandpath[0] = string("\n");
cginameandpath[1] = "";

i = 0;
if(get_port_state(port))
{
 for (i = 0; cginameandpath[i]; i = i + 1)
 {
  url = cginameandpath[i];
  if(check(req:url))exit(0);
 }
}
