# OpenVAS Vulnerability Test
# $Id: clearswift_mimesweeper_smtp_detect.nasl 57 2013-11-11 18:12:18Z jan $
# Description: Clearswift MIMEsweeper manager console detection
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
tag_summary = "The remote host appears to be running MIMEsweeper for SMTP, connections 
are allowed to the web MIMEsweeper manager console.

Letting attackers know that you are using this software will help them 
to focus their attack or will make them change their strategy.";

tag_solution = "Filter incoming traffic to this port";

if(description)
{
 script_id(18219);
 script_version("$Revision: 57 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-11 19:12:18 +0100 (Mo, 11. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 
 name = "Clearswift MIMEsweeper manager console detection";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for MIMEsweeper manager console";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 
 script_family("Service detection");
 script_dependencies("httpver.nasl");
 script_require_ports("Services/www", 80);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#da code now

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (get_port_state(port))
{
 req = http_get(item:"/MSWSMTP/Common/Authentication/Logon.aspx", port:port);
 rep = http_keepalive_send_recv(port:port, data:req);
 if( rep == NULL ) exit(0);

 if ("<title>MIMEsweeper Manager</title>" >< rep)
 {
	security_note(port);
	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
 }
}
exit(0);