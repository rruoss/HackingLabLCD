# OpenVAS Vulnerability Test
# $Id: fsp_detection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Detect FSP Compatible Hosts
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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
tag_summary = "A file transfer program is listening on the remote port.

Description :

The remote host is running a FSP (File Service Protocol)
compatible product. FSP is a protocol designed to serve file on top 
of the UDP protocol.

Make sure that the use of this program is done in accordance with your
corporate security policy.";

tag_solution = "If this service is not needed, disable it or filter incoming traffic
to this port.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
if(description)
{
 script_id(11987);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 name = "Detect FSP Compatible Hosts";
 script_name(name);

 script_description(desc);

 summary = "FSP Detection";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 script_family("Service detection");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://fsp.sourceforge.net/");
 exit(0);
}


include("misc_func.inc");

ports = make_list(21, 2000, 2221);
for ( i = 0 ; ports[i] ; i ++ )
{
 # This is UDP based protocol ...
 udpsock[i] = open_sock_udp(ports[i]);
 data = raw_string(0x10, 0x44, 0xF0, 0x33, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
 send(socket:udpsock[i], data:data);
}

for ( i = 0 ; ports[i] ; i ++ )
{
 if ( i == 0 ) z = recv(socket:udpsock, length:1024);
 else z = recv(socket:udpsock, length:1024, timeout:0);

if(z)
{
 if (z[0] == raw_string(0x10))
 {
  mlen = ord(z[7]);
  Server = "";
  for (i = 0; i < mlen - 1; i++)
   Server = string(Server, z[12+i]);

  Server -= string("\n");
  if(!get_kb_item(string("fsp/banner/", port)))
   set_kb_item(name:string("fsp/banner/", port), value:Server);

  desc += '\n\nPlugin output :\n\n' + "The remote sotware is : " + Server;
  security_warning(port:port, data:desc, protocol:"udp");
  register_service(port: port, ipproto: "udp", proto: "fsp");
  exit(0);
  }
 }
}
