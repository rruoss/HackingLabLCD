# OpenVAS Vulnerability Test
# $Id: imss_detect.nasl 57 2013-11-11 18:12:18Z jan $
# Description: Trend Micro IMSS console management detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
tag_summary = "The remote host appears to run Trend Micro Interscan Messaging Security 
Suite, connections are allowed to the web console management.

Make sure that only authorized hosts can connect to this service, as the
information of its existence may help an attacker to make more sophisticated
attacks against the remote network.";

tag_solution = "Filter incoming traffic to this port";

if(description)
{
 script_id(17244);
 script_version("$Revision: 57 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-11 19:12:18 +0100 (Mo, 11. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 
 name = "Trend Micro IMSS console management detection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for Trend Micro IMSS web console management";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 
 family = "Service detection";
 script_family(family);
 script_dependencies("httpver.nasl");
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
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
  req = http_get(item:"/commoncgi/servlet/CCGIServlet?ApHost=PDT_InterScan_NT&CGIAlias=PDT_InterScan_NT&File=logout.htm", port:port);
 
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);
 if("<title>InterScan Messaging Security Suite for SMTP</title>" >< rep)
 {
   security_note(port);
   set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
