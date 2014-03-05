# OpenVAS Vulnerability Test
# $Id: lcdproc_buffer_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: LCDproc buffer overflow
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
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
tag_summary = "LCDproc (http://lcdproc.omnipotent.net) is a 
system that is used to display system information and other data 
on an LCD display (or any supported display device, including 
curses or text)
The LCDproc version 4.0 and above uses a client-server protocol, allowing 
anyone with access to the LCDproc server to modify the displayed content.
It is possible to cause the LCDproc server to crash and execute arbitrary 
code by sending the server a large buffer that will overflow its internal 
buffer.

For more information see article:
http://www.securiteam.com/exploits/Remote_vulnerability_in_LCDproc_0_4__shell_access_.html
(NOTE: URL maybe wrapped)";

tag_solution = "Disable access to this service from outside by disabling access
 to TCP port 13666 (default port used)";

if(description)
{
 script_id(10378);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1131);
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-2000-0295");
 name = "LCDproc buffer overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Check whether LCDproc is vulnerable to attack";
 
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 family = "Buffer overflow";
 script_family(family);
 script_dependencies("find_service.nasl");
  script_require_ports("Services/lcdproc", 13666);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/lcdproc");
if(!port)port = 13666;

if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if ( ! soc ) exit(0);
  result = recv_line(socket:soc, length:4096);
  close(soc);
  if ( ! result ) exit(0);
  
  req = crap(4096);
  soc = open_sock_tcp(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = recv(socket:soc, length:4096);
   if(strlen(result) == 0)
   {
    security_hole(port:port);
    exit(0);
   }
  }
}

