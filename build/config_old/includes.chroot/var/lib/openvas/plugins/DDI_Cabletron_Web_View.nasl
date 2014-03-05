# OpenVAS Vulnerability Test
# $Id: DDI_Cabletron_Web_View.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Cabletron Web View Administrative Access
#
# Authors:
# Forrest Rae
#
# Copyright:
# Copyright (C) 2002 Digital Defense Incorporated
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
tag_summary = "This host is a Cabletron switch and is running
Cabletron WebView. This web software
provides a graphical, real-time representation of
the front panel on the switch. This graphic,
along with additionally defined areas of the
browser interface, allow you to interactively
configure the switch, monitor its status, and
view statistical information. An attacker can
use this to gain information about this host.";

tag_solution = "Depending on the location of the switch, it might
be advisable to restrict access to the web server by IP 
address or disable the web server completely.";

if(description)
{
 script_id(10962);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Cabletron Web View Administrative Access";
 script_name(name);

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
	script_description(desc);
 	summary = "Cabletron Web View Administrative Access";
	script_summary(summary);
	script_category(ACT_GATHER_INFO);
	script_copyright("This script is Copyright (C) 2002 Digital Defense Incorporated");
	family = "Privilege escalation";
	script_family(family);
	script_dependencies("find_service.nasl");
    script_require_ports("Services/www");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{
	soc = http_open_socket(port);
	if(soc)
	{
		req = http_get(item:string("/chassis/config/GeneralChassisConfig.html"), port:port);
		send(socket:soc, data:req);
		
		r = http_recv(socket:soc);
		     
		if("Chassis Configuration" >< r)
		{
			security_hole(port:port); 
			set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
			exit(0);
		}

		http_close_socket(soc);
	}
}



