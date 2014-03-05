# OpenVAS Vulnerability Test
# $Id: netasq.nasl 17 2013-10-27 14:01:43Z jan $
# Description: NetAsq identification
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) Copyright (C) 2004 David Maciejak
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
tag_summary = "It's very likely that this remote host is a NetAsq IPS-Firewalls
with port TCP/1300 open to allow Firewall Manager tool to
remotely configure it.

Letting attackers know that you are using a NetAsq 
will help them to focus their attack or will 
make them change their strategy. 

You should not let them know such information.";

tag_solution = "do not allow any connection on the
firewall itself, except from trusted network.";

if(description)
{
 script_id(14378);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 name = "NetAsq identification";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution + "

";


 script_description(desc);
 
 summary = "Determines if the remote host is a NetAsq";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Firewalls";
 script_family(family);
 script_require_ports(1300);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.netasq.com");
 exit(0);
}

#
# The script code starts here
#

port=1300;

if (get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(!soc)exit(0);
 req=string("OPENVAS\r\n");
 send(socket:soc, data:req);
 r=recv(socket:soc,length:512);
 
 if (ereg(pattern:"^200 code=[0-9]+ msg=.*", string:r))
 {
 	req=string("QUIT\r\n");
 	send(socket:soc, data:req);
 	r=recv(socket:soc,length:512);
	if (ereg(pattern:"^103 code=[0-9]+ msg=.*\.\.\.", string:r))
	{
		security_warning(port);
	}
 }
 close(soc);
}
exit(0);
