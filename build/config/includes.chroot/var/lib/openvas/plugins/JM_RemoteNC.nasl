# OpenVAS Vulnerability Test
# $Id: JM_RemoteNC.nasl 17 2013-10-27 14:01:43Z jan $
# Description: RemoteNC detection
#
# Authors:
# Joseph Mlodzianowski <joseph@rapter.net>
# thanks to H.D.Moore
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-07-06
# Removed the CVSS Base and Risk Factor 
#
# Copyright:
# Copyright (C) 2003 J.Mlodzianowski
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
tag_summary = "This host appears to be running RemoteNC on this port

RemoteNC is a Backdoor which allows an intruder gain
remote control of your computer.

An attacker may use it to steal your passwords.";

tag_solution = "see www.rapter.net/jm2.htm for details on removal";

if(description)
{

 script_id(11855);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "RemoteNC detection";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Determines the presence of RemoteNC";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2003 J.Mlodzianowski");
 family = "Malware";
 script_family(family);
 script_dependencies("find_service2.nasl", "JM_FsSniffer.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


#
# The code starts here
#

include("misc_func.inc");

port = get_kb_item("Services/RemoteNC");
if (!port) exit(0);

if(!get_port_state(port))exit(0);

soc = open_sock_tcp(port);
if(!soc) exit(0);

r = recv(socket:soc, min:1, length:30);
if(!r) exit(0);

if("RemoteNC Control Password:" >< r)  security_hole(port);
