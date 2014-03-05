# OpenVAS Vulnerability Test
# $Id: korgo.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Korgo worm detection
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "The remote host is probably infected with Korgo worm.
It propagates by exploiting the LSASS vulnerability on TCP port 445 
(as described in Microsoft Security Bulletin MS04-011)
and opens a backdoor on TCP ports 113 and 3067.";

tag_solution = "- Disable access to port 445 by using a firewall
- Apply Microsoft MS04-011 patch.";

if(description)
{
 script_id(12252);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "Korgo worm detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution; 
 script_description(desc);
 summary = "Korgo worm detection";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports(113, 3067);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://securityresponse.symantec.com/avcenter/venc/data/w32.korgo.c.html");
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS04-011.mspx");
 exit(0);
}

#
# The script code starts here
#
ports[0] =  3067;           
ports[1] =  113;

if (get_port_state(ports[0]))
{
	soc1 = open_sock_tcp(ports[0]);
	if (soc1) 
	{	
		if (get_port_state(ports[1]))
		{
			soc2 = open_sock_tcp(ports[1]);
			if (soc1 && soc2)
			{	
				close(soc1);
				close(soc2);
				security_hole(ports[0]);
			}
		}
	}
}
exit(0);
