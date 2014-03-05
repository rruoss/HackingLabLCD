# OpenVAS Vulnerability Test
# $Id: securemote.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Checkpoint SecureRemote detection
#
# Authors:
# Yoav Goldberg <yoavg@securiteam.com>
#
# Copyright:
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
tag_summary = "The remote host seems to be a Checkpoint FW-1 running SecureRemote.
Letting attackers know that you are running FW-1 may enable them to
focus their attack or will make them change their attack strategy.
You should not let this information leak out.
Furthermore, an attacker can perform a denial of service attack on the
machine.";

tag_solution = "Restrict access to this port from untrusted networks.

For More Information:
http://www.securiteam.com/securitynews/CheckPoint_FW1_SecureRemote_DoS.html";


if(description)
{
 script_name("Checkpoint SecureRemote detection");
 script_id(10617);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"1.2");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Low");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc); 
 script_summary("Determine if a remote host is running CheckPoint's SecureRemote");
 script_category(ACT_GATHER_INFO);
 script_family("Firewalls");
 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 script_require_ports(264);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# Actual script starts here
#

SecureRemote = 0;

buffer1 = raw_string(0x41, 0x00, 0x00, 0x00);
buffer2 = raw_string(0x02, 0x59, 0x05, 0x21);

if(get_port_state(264))
	{
	soc = open_sock_tcp(264);
	if(soc)
		{
		send(socket:soc, data:buffer1);
		send(socket:soc, data:buffer2);
		response = recv(socket:soc, length:5);
		if (response == buffer1) {
				SecureRemote = 1;}
 		close(soc);	
		}
	}

if(SecureRemote)
{	
	set_kb_item(name:"Host/firewall", value:"Checkpoint Firewall-1");
	security_note(264);
}
