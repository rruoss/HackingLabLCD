# OpenVAS Vulnerability Test
# $Id: tomcat_status.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Tomcat /status information disclosure
#
# Authors:
# Vincent Renardias <vincent@strongholdnet.com>
#
# Copyright:
# Copyright (C) 2003 StrongHoldNet
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
tag_summary = "Requesting the URI /status gives information about
the currently running Tomcat.

It also allows anybody to reset (ie: permanently delete) the current
statistics.";

tag_solution = "If you don't use this feature, comment the appropriate section in
your httpd.conf file. If you really need it, limit its access to
the administrator's machine.";

if(description)
{
 script_id(11218);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_tag(name:"risk_factor", value:"High");
 name = "Tomcat /status information disclosure";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Makes a request like http://www.example.com/server-status";
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2003 StrongHoldNet");
 script_family("Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 
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
  buffer = http_get(item:"/status", port:port);
  data = http_keepalive_send_recv(port:port, data:buffer);
  if( ("Status information for" >< data) && ("<a href='jkstatus?scoreboard.reset'>reset</a>" >< data) )
   security_hole(port);
}

