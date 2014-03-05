# OpenVAS Vulnerability Test
# $Id: rtsp_detect.nasl 41 2013-11-04 19:00:12Z jan $
# Description: RTSP Server type and version
#
# Authors:
# Georges Dagousset <georges.dagousset@alert4web.com>
#
# Copyright:
# Copyright (C) 2001 Alert4Web.com
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
tag_summary = "This detects the RTSP Server's type and version.

This information gives potential attackers additional information about the
system they are attacking. Server and Version should be omitted
where possible.";

tag_solution = "Change the server name";

if(description)
{
 script_id(10762);
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "RTSP Server type and version";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "RTSP Server detection";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 family = "General";
 script_family(family);
 script_dependencies("find_service2.nasl");
 script_require_ports("Services/rtsp", 554);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
 include("misc_func.inc");
 not_in_kb = 0;
 port = get_kb_item("Services/rtsp");
 if(!port) { port = 554; not_in_kb = 1; }
 if (get_port_state(port))
 {
  soc = open_sock_tcp(port);
  if (soc)
  {
   data = string("OPTIONS * RTSP/1.0\r\n\r\n");
   send(socket:soc, data:data);
   header = recv(socket:soc, length:1024);
   if(("RTSP/1" >< header) && ("Server:" >< header)) {
     if ( not_in_kb != 0 ) register_service(proto:"rtsp", port:port);
     server = egrep(pattern:"Server:",string:header);
     if (server) {
      set_kb_item(name:string("RTSP/",port,"/Server"), value: server); 
      report = string("The remote RTSP server is :\n",server,"\nWe recommend that you configure your server to return\nbogus versions in order to not leak information\n");
      security_note(port:port, data:report);
     }
     security_note(port:port, data:string("All RTSP Header for 'OPTIONS *' method:\n",header));
   }
  close(soc);
  }
 }
