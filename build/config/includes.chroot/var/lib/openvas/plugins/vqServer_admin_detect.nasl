# OpenVAS Vulnerability Test
# $Id: vqServer_admin_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: vqServer administrative port
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#	- solution
#	- script id
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
tag_summary = "vqSoft's vqServer administrative port is open. Brute force guessing of the 
username/password is possible, and a bug in versions 1.9.9 and below 
allows configuration file retrieval remotely.

For more information, see:
http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html";

tag_solution = "close this port for outside access.";

if(description)
{
 script_id(10354);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1610);
 script_cve_id("CVE-2000-0766");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "vqServer administrative port";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Detect vqServer's administrative port";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 family = "General";
 script_family(family);
 
 script_require_ports("Services/vqServer-admin", 9090);
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
include("http_func.inc");

port = get_kb_item("Services/vqServer-admin");
if(!port)port = 9090;
if (get_port_state(port))
{
 soctcp9090 = http_open_socket(port);

 if (soctcp9090)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp9090, data:sendata);
  banner = http_recv(socket:soctcp9090);
  http_close_socket(soctcp9090);
  
  if (("Server: vqServer" >< banner) && ("WWW-Authenticate: Basic realm=/" >< banner))
  {
    resultrecv = strstr(banner, "Server: ");
    resultsub = strstr(resultrecv, string("\n"));
    resultrecv = resultrecv - resultsub;
    resultrecv = resultrecv - "Server: ";
    resultrecv = resultrecv - "\n";
   
    banner = string("vqServer version is : ");
    banner = banner + resultrecv;
    security_hole(port);
    security_hole(port:port, data:banner);
  }
 }
}

