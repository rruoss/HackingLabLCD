# OpenVAS Vulnerability Test
# $Id: mycio_directory_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: McAfee myCIO Directory Traversal
#
# Authors:
# Noam Rathaus <noamr@securiteam.com> 
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
tag_summary = "The remote host runs McAfee's myCIO HTTP Server, which is vulnerable to Directory Traversal.
A security vulnerability in the product allows attackers to traverse outside the normal HTTP root path, and this exposes access to sensitive files.";

tag_solution = "Configure your firewall to block access to this port (TCP 6515). Use the Auto Update feature of McAfee's myCIO to get the latest version.";

if(description)
{
 script_id(10706); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3020);
 script_cve_id("CVE-2001-1144");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "McAfee myCIO Directory Traversal";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "McAfee myCIO Directory Traversal";
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 family = "Remote file access";
 script_family(family);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/mycio", 6515);
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

port = get_kb_item("Services/mycio");
if (!port) port = 6515;

if(get_port_state(port))
{
 banner = get_http_banner(port:port);
 if(!banner)exit(0);
 
 if ("myCIO" >< banner)
 {
  soctcp6515 = http_open_socket(port);
  data = http_get(item:string(".../.../.../"), port:port);
  resultsend = send(socket:soctcp6515, data:data);
  resultrecv = http_recv(socket:soctcp6515);
  http_close_socket(soctcp6515);
  if ("Last Modified" >< resultrecv) security_warning(port:port);
 }
}
 
