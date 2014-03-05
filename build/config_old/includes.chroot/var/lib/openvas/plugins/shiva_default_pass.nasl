# OpenVAS Vulnerability Test
# $Id: shiva_default_pass.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Shiva Integrator Default Password
#
# Authors:
# Stefaan Van Dooren <stefaanv@kompas.be>
#
# Copyright:
# Copyright (C) 2000 Stefaan Van Dooren
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
tag_summary = "The remote Shiva router uses the default password. 
This means that anyone who has (downloaded) a user manual can 
telnet to it and reconfigure it to lock you out of it, and to 
prevent you to use your internet connection.";

tag_solution = "telnet to this router and set a different password immediately.";

if(description)
{
	script_id(10500);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  	script_cve_id("CVE-1999-0508");
    script_tag(name:"cvss_base", value:"4.6");
    script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
    script_tag(name:"risk_factor", value:"Medium");
	name = "Shiva Integrator Default Password";
	script_name(name);
 
	desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

	script_description(desc);
 
	summary = "Logs into the remote Shiva router";
	script_summary(summary);
 
	script_category(ACT_GATHER_INFO);
 
	script_copyright("This script is Copyright (C) 2000 Stefaan Van Dooren");
	family = "General";
	script_family(family);
	script_require_ports(23);
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}

#
# The script code starts here
#
port = 23;
if(get_port_state(port))
{
	soc = open_sock_tcp(port);
	if(soc)
	{
		data = string("hello\n\r");
		send(data:data, socket:soc);
		buf = recv(socket:soc, length:4096);
		if ("ntering privileged mode" >< buf)
			security_warning(port);
		close(soc);
	}
}

