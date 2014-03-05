# OpenVAS Vulnerability Test
# $Id: vqServer_web_traversal.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Anaconda Double NULL Encoded Remote File Retrieval
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Changes by rd :
#	- changed the request to GET / HTTP/1.0 (and not GET / HEAD/1.0)
#	- script id
#	- changed family to Remote file access
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
tag_summary = "vqSoft's vqServer web server (version 1.9.9 and below) has been detected.
This version contains a security vulnerability that allows attackers to request any file,
even if it is outside the HTML directory scope.

For more information:
http://www.securiteam.com/windowsntfocus/Some_Web_servers_are_still_vulnerable_to_the_dotdotdot_vulnerability.html";

tag_solution = "Upgrade to the latest version, available from: http://www.vqsoft.com.";

if(description)
{
 script_id(10355);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(1067);
script_cve_id("CVE-2000-0240");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "vqServer web traversal vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Detect vqServer's web traversal bug";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 SecuriTeam");
 family = "Remote file access";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
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

port = get_http_port(default:80);

if (get_port_state(port))
{
 soctcp80 = http_open_socket(port);

 if (soctcp80)
 {
  sendata = http_get(item:"/", port:port);
  send(socket:soctcp80, data:sendata);
  banner = http_recv(socket:soctcp80);
  http_close_socket(soctcp80);
  
  if ("Server: vqServer" >< banner)
  {
   resultrecv = strstr(banner, "Server: ");
   resultsub = strstr(resultrecv, string("\n"));
   resultrecv = resultrecv - resultsub;
   resultrecv = resultrecv - "Server: ";
   resultrecv = resultrecv - string("\n");
   
   if(egrep(string:resultrecv, pattern:"vqServer/(0\.|1\.([0-8]\.|9\.[0-9])"))
   {
    banner = string("vqServer version is : ");
    banner = banner + resultrecv;
    security_warning(port);
    security_warning(port:port, data:banner);
   }
  }
 }
}
