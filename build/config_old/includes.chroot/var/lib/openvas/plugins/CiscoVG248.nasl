# OpenVAS Vulnerability Test
# $Id: CiscoVG248.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Cisco VG248 login password is blank
#
# Authors:
# Rick McCloskey <rpm.security@gmail.com>
#
# Copyright:
# Copyright (C) 2005 Rick McCloskey
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
tag_summary = "The remote host is a Cisco VG248 with a blank password.

The Cisco VG248 does not have a password set and allows direct
access to the configuration interface. An attacker could telnet 
to the Cisco unit and reconfigure it to lock the owner out as 
well as completely disable the phone system.";

tag_solution = "Telnet to this unit and at the configuration interface:
Choose Configure-> and set the login and enable passwords. If 
possible, in the future do not use telnet since it is an insecure protocol.";

# Cisco VG248 with a blank password nasl script. - non intrusive
# 
# Tested against production systems with positive results. 
# This cisco unit does not respond to the other "Cisco with no password" 
# nasl scripts.

if(description)
{
   script_id(19377);
   script_version("$Revision: 17 $");
   script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
   script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
   script_tag(name:"cvss_base", value:"10.0");
   script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
   script_tag(name:"risk_factor", value:"Critical");
   
   name = "Cisco VG248 login password is blank";
   script_name(name);
 
   desc = "
   Summary:
   " + tag_summary + "
   Solution:
   " + tag_solution;
   script_description(desc);
 
   summary = "The remote host is a Cisco VG248 with a blank password.";
   script_summary(summary);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright("This script is Copyright (C) 2005 Rick McCloskey");
   script_family("CISCO");
 
   if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
     script_tag(name : "solution" , value : tag_solution);
     script_tag(name : "summary" , value : tag_summary);
   }
   exit(0);
}

include('telnet_func.inc');
port = get_kb_item("Services/telnet");
if ( ! port ) port = 23;
if ( ! get_port_state(port)) exit (0);

if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if ( ! soc ) exit (0);
 banner = telnet_negotiate(socket:soc);
 banner += line = recv_line(socket:soc, length:4096);
 n  = 0;
 while( line =~ "^ ")
	{
   		line = recv_line(socket:soc, length:4096);
		banner += line;
		n ++;
		if ( n > 100 ) exit(0); # Bad server ?
	}
   close(soc);
   if ( "Main menu" >< banner && "Configure" >< banner && "Display" >< banner )
	{
		security_hole(port);
	}
 
}

