# OpenVAS Vulnerability Test
# $Id: webserver_robot.nasl 17 2013-10-27 14:01:43Z jan $
# Description: robot(s).txt exists on the Web Server
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
tag_insight = "By connecting to the server and requesting the /robot(s).txt file, an
attacker may gain additional information about the system they are
attacking.

Such information as, restricted directories, hidden directories, cgi script
directories and etc. Take special care not to tell the robots not to index
sensitive directories, since this tells attackers exactly which of your
directories are sensitive.";
tag_summary = "Some Web Servers use a file called /robot(s).txt to make search engines and
any other indexing tools visit their WebPages more frequently and
more efficiently.";

 head = "
 Summary:
 " + tag_summary + "
 Vulnerability Insight:
 " + tag_insight;

if(description)
{
 script_id(10302);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "robot(s).txt exists on the Web Server";
 script_name(name);
 
 desc = head;

 script_description(desc);
 
 summary = "robot(s).txt exists on the Web Server";
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 1999 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");
port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/no404") ) exit(0);

res = is_cgi_installed_ka(port:port, item:"/robot.txt");
if(res)
{
 sockwww = http_open_socket(port);
 if (sockwww)
 {
  sendata = http_get(item:"/robot.txt", port:port);
  send(socket:sockwww, data:sendata);
  headers = http_recv_headers2(socket:sockwww);
  body = http_recv_body(socket:sockwww, headers:headers, length:0);
  if("llow" >< body || "agent:" >< body)
   {
   if (body)
    {
    body = string("The file 'robot.txt' contains the following:\n", body);
    security_note(port:port, data:head + body);
    }
   http_close_socket(sockwww);
  }
 }
 else exit(0);
}
else
{
 res = is_cgi_installed_ka(port:port, item:"/robots.txt");
 if(res)
 {
  sockwww = http_open_socket(port);
  if (sockwww)
  {
   sendata = http_get(item:"/robots.txt", port:port);
   send(socket:sockwww, data:sendata);
   headers = http_recv_headers2(socket:sockwww);
   body = http_recv_body(socket:sockwww, headers:headers, length:0);
  if("llow" >!< body && "agent:" >!< body)exit(0);
   
   if (body)
   {
    body = string("The file 'robots.txt' contains the following:\n", body);
    security_note(port:port, data:head + body);
   }
   http_close_socket(sockwww);
  }
 }
}
