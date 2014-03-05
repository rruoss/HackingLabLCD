# OpenVAS Vulnerability Test
# $Id: ossim_server_detect.nasl 16 2013-10-27 13:09:52Z jan $
# Description: OSSIM Server Detection
#
# Authors:
# Ferdy Riphagen 
#
# Copyright:
# Copyright (C) 2007 Ferdy Riphagen
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
tag_summary = "A OSSIM server is listening on the remote system. 

Description :

The remote system is running an OSSIM server. OSSIM (Open Source
Security Information Management) is a centralized security management 
information system.";

tag_solution = "If possible, filter incoming connections to the service so that it is
used by trusted sources only.";

if (description) {
 script_id(9000001);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-21 14:43:25 +0200 (Thu, 21 Aug 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 name = "OSSIM Server Detection";
 script_name(name);
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 summary = "Checks for a OSSIM server on the default port tcp/40001";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2007 Ferdy Riphagen");

 script_dependencies("find_service1.nasl");
 script_require_ports("Services/unknown", 40001);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.ossim.net");
 exit(0);
}

include("misc_func.inc");

port = get_unknown_svc(40001);
if (!port) port = 40001;
if (known_service(port:port)) exit(0);
if (!get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (soc) { 
	rand = rand() % 10;
	data = 'connect id="' + rand + '" type="sensor"\n'; 
	send(socket:soc, data:data);
	recv = recv(socket:soc, length:64);

	if (recv == 'ok id="' + rand + '"\n') {
		security_note(port:port);
		register_service(port:port, ipproto:"tcp", proto:"ossim_server");
	}
}
exit(0);
