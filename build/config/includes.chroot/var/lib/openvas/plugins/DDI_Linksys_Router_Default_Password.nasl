# OpenVAS Vulnerability Test
# $Id: DDI_Linksys_Router_Default_Password.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Linksys Router Default Password
#
# Authors:
# Forrest Rae <forrest.rae@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
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
tag_summary = "This Linksys Router has the default password 
set for the web administration console. 
This console provides read/write access to the
router's configuration. An attacker could take
advantage of this to reconfigure the router and 
possibly re-route traffic.";

tag_solution = "Please assign the web administration
          console a difficult to guess password.";

if(description)
{
	script_id(10999);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"Medium");
	script_cve_id("CVE-1999-0508");
	name = "Linksys Router Default Password";
	script_name(name);
	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;	script_description(desc);
	summary = "Linksys Router Default Password";
	script_summary(summary);
	script_category(ACT_GATHER_INFO);
	script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
	family = "General";
	script_family(family);
	script_dependencies("find_service.nasl");
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

if (!get_port_state(port))port = 8080;

if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if (soc)
	{
	
		# HTTP auth = ":admin"
		# req = string("GET / HTTP/1.0\r\nAuthorization: Basic OmFkbWlu\r\n\r\n");
		
		# HTTP auth = "admin:admin"
		req = string("GET / HTTP/1.0\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");
		
		# Both work, second is used to be RFC compliant.
		
		send(socket:soc, data:req);
		buf = http_recv(socket:soc);
		
		close(soc);
		if (("Status.htm" >< buf) && ("DHCP.htm" >< buf) && ("Log.htm" >< buf) && ("Security.htm" >< buf) ||
		    ("next_file=Setup.htm" >< buf && "Checking JavaScript Support" >< buf) #WAG120N
		    )
		{
			security_warning(port:port);
		}
	}
}
