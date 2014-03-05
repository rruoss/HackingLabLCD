# OpenVAS Vulnerability Test
# $Id: 4553.nasl 17 2013-10-27 14:01:43Z jan $
# Description: 4553 Parasite Mothership Detect
#
# Authors:
# Chris Gragsone
#
# Copyright:
# Copyright (C) 2002 Violating
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
tag_solution = "re-install this host";
tag_summary = "The backdoor '4553' seems to be installed on this host, which indicates
it has been compromised.";


if(description) {
	script_id(11187);
	script_version("$Revision: 17 $");
    script_tag(name:"cvss_base", value:"9.3");
    script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
    script_tag(name:"risk_factor", value:"Critical");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

    script_name("4553 Parasite Mothership Detect");
	script_description(desc);
	script_summary("Detects the presence of 4553 parasite's mothership");
	script_category(ACT_GATHER_INFO);
	script_copyright("This script is Copyright (C) 2002 Violating");
	script_family("Malware");
	script_require_ports(21227, 21317);
	
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}



targets = make_list(21227, 21317);
foreach target (targets)
{
 if(get_port_state(target)) 
 {
 soc = open_sock_tcp(target);
 if(!soc)exit(0);
 send(socket:soc, data:"-0x45-");
 data = recv(socket:soc, length:1024);

 if(("0x53" >< data) || ("<title>UNAUTHORIZED-ACCESS!</title>" >< data)) 
  {
	security_hole(target);
  }
 }
}
