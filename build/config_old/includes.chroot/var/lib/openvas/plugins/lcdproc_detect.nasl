# OpenVAS Vulnerability Test
# $Id: lcdproc_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: LCDproc server detection
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
on an LCD display (or any supported display device, including curses 
or text).
 
The LCDproc version 0.4 and above uses a client-server protocol, allowing 
anyone with access to the LCDproc server to modify the displayed content.";

tag_solution = "Disable access to this service from outside by disabling
 access to TCP port 13666 (default port used).";

if(description)
{
 script_id(10379);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 name = "LCDproc server detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
  script_description(desc);
 
  summary = "Find the presence of LCDproc";
 
  script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
  script_copyright("This script is Copyright (C) 2000 SecuriTeam");
  script_family("Service detection");
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
  req = string("hello");
  soc = open_sock_tcp(port);
  if(soc)
  {
   send(socket:soc, data:req);
   result = recv(socket:soc, length:4096);
   
   if("connect LCDproc" >< result)
   {
    resultrecv = strstr(result, "connect LCDproc ");
    resultsub = strstr(resultrecv, string("lcd "));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "connect LCDproc ";
    resultrecv = resultrecv - "lcd ";

    banner = "LCDproc (";
    banner = banner + resultrecv;
    banner = banner + ') was found running on the target.\n';

    security_warning(port:port, data:banner);
    exit(0);
   }
  }
}

