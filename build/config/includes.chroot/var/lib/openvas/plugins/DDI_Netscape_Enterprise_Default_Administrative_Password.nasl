# OpenVAS Vulnerability Test
# $Id: DDI_Netscape_Enterprise_Default_Administrative_Password.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Netscape Enterprise Default Administrative Password
#
# Authors:
# Forrest Rae <forrest.rae@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2003 Digital Defense Inc.
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
tag_summary = "This host is running the Netscape Enterprise Server.  The Administrative 
interface for this web server, which operates on port 8888/TCP, is using
the default username and password of 'admin'.  An attacker can use this to 
reconfigure the web server, cause a denial of service condition, or
gain access to this host.";

tag_solution = "Please assign the web administration console a difficult to guess
password.";

if(description)
{
	script_id(11208);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"7.5");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"High");
	name = "Netscape Enterprise Default Administrative Password";
	script_cve_id("CVE-1999-0502");
	script_name(name);
	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;	script_description(desc);
	summary = "Netscape Enterprise Default Administrative Password";
	script_summary(summary);
	script_category(ACT_GATHER_INFO);
	script_copyright("This script is Copyright (C) 2003 Digital Defense Inc.");
	family = "General";
	script_family(family);
	script_require_ports("Services/www", 8888);
	script_dependencies("find_service.nasl");
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

debug = 0;

ports = add_port_in_list(list:get_kb_list("Services/www"), port:8888);

foreach port (ports)
{
	if ( !get_port_state(port) ) continue;
	banner = get_http_banner(port:port);
	if ( ! banner || ("Netscape" >!< banner && "iPlanet" >!< banner ) ) continue;
	soc = http_open_socket(port);
	
	if (soc)
	{
		
		# HTTP auth = "admin:admin"
		
		
		req = http_get(item:"/https-admserv/bin/index", port:port);
    		req = req - string("\r\n\r\n");
    		req = string(req, "\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n");
    
		
		send(socket:soc, data:req);
		buf = http_recv(socket:soc);
		
		if(debug == 1) display("\n\n", buf, "\n\n");
		
		http_close_socket(soc);
		
		if (("Web Server Administration Server" >< buf) && ("index?tabs" >< buf))
		{
			security_hole(port:port);
		}
	}
}
