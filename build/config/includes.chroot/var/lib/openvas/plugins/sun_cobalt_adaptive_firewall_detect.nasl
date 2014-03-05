# OpenVAS Vulnerability Test
# $Id: sun_cobalt_adaptive_firewall_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sun Cobalt Adaptive Firewall Detection
#
# Authors:
# SecurITeam
#
# Copyright:
# Copyright (C) 2002 SecurITeam
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
tag_summary = "Sun Cobalt machines contain a firewall mechanism, this mechanism can be
configured remotely by accessing Cobalt's built-in HTTP server. Upon access to
the HTTP server, a java based administration program would start, where a user
is required to enter a pass phrase in order to authenticate himself. Since no
username is required, just a passphrase bruteforcing of this interface is
easier.";

tag_solution = "Access to this port (by default set to port 8181) should not be permitted from
the outside. Further access to the firewall interface itself should not be
allowed (by default set to port 2005).";

if(description)
{
 script_id(10878);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Sun Cobalt Adaptive Firewall Detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Sun Cobalt Adaptive Firewall Detection";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 SecurITeam");
 family = "General";
 script_family(family);
 script_dependencies("httpver.nasl");
 script_require_ports("Services/www", 8181);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

# Check starts here

function check(port, req)
{
  req = http_get(item:req, port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if( buf == NULL ) exit(0);
  
  if (("Sun Cobalt Adaptive Firewall" >< buf) && ("One moment please" >< buf))
  {
   	security_warning(port:port);
 	set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
	exit(0);
  }
 return(0);
}


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8181);

foreach port (ports)
{
 foreach dir (cgi_dirs()) check(port:port, req:string(dir, "/"));
}
