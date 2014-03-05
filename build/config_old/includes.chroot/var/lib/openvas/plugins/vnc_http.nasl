# OpenVAS Vulnerability Test
# $Id: vnc_http.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Check for VNC HTTP
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
tag_summary = "The remote server is running VNC.
VNC permits a console to be displayed remotely.";

tag_solution = "Disable VNC access from the network by
using a firewall, or stop VNC service if not needed.";

if(description)
{
 script_id(10758);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 name = "Check for VNC HTTP";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;




 script_description(desc);
 
 summary = "Detects the presence of VNC HTTP";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2001 Alert4Web.com");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 5800, 5801, 5802);
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
include("misc_func.inc");

function probe(port)
{
 banner = get_http_banner(port:port);
 if(banner)
 {
  if (("vncviewer.jar" >< banner) || ("vncviewer.class" >< banner))
  {
   security_warning(port);
   set_kb_item(name:"www/vnc", value:TRUE);
  }
 }
}


ports = add_port_in_list(list:get_kb_list("Services/www"), port:5800);
ports = add_port_in_list(list:ports, port:5801);
ports = add_port_in_list(list:ports, port:5802);

foreach port (ports)
{
  probe(port:port);
}

