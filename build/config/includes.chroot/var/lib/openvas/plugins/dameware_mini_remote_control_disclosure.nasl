# OpenVAS Vulnerability Test
# $Id: dameware_mini_remote_control_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: DameWare Mini Remote Control Information Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2003 Noam Rathaus
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
tag_summary = "The remote host is running DameWare Mini Remote Control.
This program allows remote attackers to determine the OS type and
which Service Pack is installed on the server.";

tag_solution = "Filter out incoming traffic to this port to minimize the
threat.";

if(description)
{
 script_id(11968);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "DameWare Mini Remote Control Information Disclosure";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "DameWare Mini Remote Control Information Disclosure";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 Noam Rathaus");
 family = "General";
 script_family(family);
 script_require_ports(6129, "Services/dameware");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here
debug = 0;
port = get_kb_item("Services/dameware");
if (! port) port = 6129;

if (debug)
{
 include("dump.inc");
}

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  rec = recv(socket:soc, length:8192);

  if (debug)
  {
   dump(ddata:rec,dtitle:"DameWare");
  }

  if (!((rec[0] == raw_string(0x30)) && (rec[1] == raw_string(0x11))))
  {
   exit(0);
  }

  rec = insstr(rec, raw_string(0x00), 28, 28);
  rec = insstr(rec, raw_string(0x01), 36, 36);

  send(socket:soc, data:rec);

  rec = recv(socket:soc, length:8192);

  if (debug)
  {
   dump(ddata:rec,dtitle:"DameWare");
  }

  if (!((rec[0] == raw_string(0x10)) && (rec[1] == raw_string(0x27))))
  {
   exit(0);
  }

  windows_version = "";
  if ((rec[16] == raw_string(0x28)) && (rec[17] == raw_string(0x0a)))
  {
   windows_version = "Windows XP";
   if (debug)
   {
    display("Windows XP - ");
   }
  }
  if ((rec[16] == raw_string(0x93)) && (rec[17] == raw_string(0x08)))
  {
   windows_version = "Windows 2000";
   if (debug)
   {
    display("Windows 2000 - ");
   }
  }
  if (windows_version == "")
  {
   exit(0);
  }

  service_pack = "";
  for (i = 24; rec[i] != raw_string(0x00); i = i + 1)
  {
   service_pack = string(service_pack, rec[i]);
  }

  if (debug)
  {
   display(service_pack);
   display("\n");
  }

  report = 
"Using DameWare mini remote control, it was possible to determine that the 
remote host is running ";
  report = string(report, windows_version);
  report = string(report, " - ");
  report = string(report, service_pack);

  security_note(port:port, data:report);
 } 
}
