# OpenVAS Vulnerability Test
# $Id: stonegate_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: StoneGate client authentication detection
#
# Authors:
# Holger Heimann <hh@it-sec.de>
#
# Copyright:
# Copyright (C) 2003 it.sec/Holger Heimann
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
tag_summary = "A StoneGate firewall login is displayed. 

If you see this from the internet or an not administrative
internal network it is probably wrong.";

tag_solution = "Restrict incoming traffic to this port";

if(description)
{
 script_id(11762);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"risk_factor", value:"None");
 
 name = "StoneGate client authentication detection";
 
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Check for StoneGate firewall client authentication prompt";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2003 it.sec/Holger Heimann");

 family = "Firewalls";

 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/SG_ClientAuth", 2543);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}



function test_stonegate(port)
{
  r = get_kb_item("FindService/tcp/" + port + "/spontaneous");
  if ( ! r ) return 0;
  match = egrep(pattern:"(StoneGate firewall|SG login:)", string : r); 
  if(match)
	return(r);
  else	
  	return(0);
}


## Heres the real dialog:
#
#	 telnet www.xxxxxx.de 2543
#	Trying xxx.xxx.xxx.xxx ...
#	Connected to www.xxxxs.de.
#	Escape character is '^]'.
#	StoneGate firewall (xx.xx.xx.xx) 
#	SG login: 


port = get_kb_item("Services/SG_ClientAuth");
if(!port)port = 2543;
if(!get_port_state(port))exit(0);


r = test_stonegate(port:port);

if (r != 0)
{
	data = "
A StoneGate firewall client authentication  login is displayed.

Here is the banner :

" + r + "


If you see this from the internet or an not administrative
internal network it is probably wrong.

Solution: Restrict incoming traffic to this port.";

	security_warning(port:port, data:data);
	exit(0);
}
