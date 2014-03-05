# OpenVAS Vulnerability Test
# $Id: sitescope_web_admin_server.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SiteScope Web Administration Server Detection
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
tag_summary = "The remote web server is running the SiteScope Administration 
web server. This server enables attackers to configure your SiteScope product 
(Firewall monitoring program) if they gain access to a valid authentication 
username and password or to gain valid usernames and passwords using
a brute force attack.";

tag_solution = "Disable the SiteScope Administration web server if it is unnecessary,
or block incoming traffic to this port.";

if(description)
{
 script_id(10741); 
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium"); 
 name = "SiteScope Web Administration Server Detection";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "SiteScope Web Administration Server Detect";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 2525);
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
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:2525);
foreach port (ports)
{
  buf = http_get_cache(item:"/", port:port);
  if (("401 Unauthorized" >< buf) && ("WWW-Authenticate: BASIC realm=" >< buf) && ("SiteScope Administrator" >< buf))
   security_warning(port:port);
}
