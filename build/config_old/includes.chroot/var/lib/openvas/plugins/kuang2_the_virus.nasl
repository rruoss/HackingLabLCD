# OpenVAS Vulnerability Test
# $Id: kuang2_the_virus.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Kuang2 the Virus
#
# Authors:
# Scott Adkins <sadkins@cns.ohiou.edu>
#
# Copyright:
# Copyright (C) 2000 Scott Adkins
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
tag_solution = "Disinfect the computer with the latest copy of
 virus scanning software.  Alternatively, you can
 find a copy of the virus itself on the net by 
 doing an Altavista search.  The virus comes with
 the server, client and infector programs.  The
 client program not only allows you to remotely
 control infected machines, but disinfect the 
 machine the client is running on.";

 tag_summary = "Kuang2 the Virus was found.

 Kuang2 the Virus is a program that infects all
 the executables on the system, as well as set up
 a server that allows the remote control of the
 computer.  The client program allows files to be
 browsed, uploaded, downloaded, hidden, etc on the
 infected machine.  The client program also  can
 execute programs on the remote machine.

 Kuang2 the Virus also has plugins that can be used
 that allows the client to do things to the remote
 machine, such as hide the icons and start menu, 
 invert the desktop, pop up message windows, etc.

 More Information:
 http://vil.mcafee.com/dispVirus.asp?virus_k=10213";
 
if (description)
{
 script_id(10132);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 script_cve_id("CVE-1999-0660");
 name = "Kuang2 the Virus";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Checks for Kuang2 the Virus";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2000 Scott Adkins");

 family = "Malware";
 script_family(family);

 script_dependencies("find_service.nasl");
 script_require_ports(17300);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#

port = 17300;
if (get_port_state(port))
{
    soc = open_sock_tcp(port);
    if (soc) {
	data = recv_line(socket:soc, length:100);
	if(!data)exit(0);
	if ("YOK2" >< data) security_hole(port);
        close(soc);
    }
}