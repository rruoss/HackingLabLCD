# OpenVAS Vulnerability Test
# $Id: citrix.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Citrix published applications
#
# Authors:
# John Lampe <j_lampe@bellsouth.net>
# Based on Citrix Published Application Scanner version 2.0
# by Ian Vitek, ian.vitek@ixsecurity.com
#
# Copyright:
# Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net
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
tag_summary = "Attempt to enumerate Citrix published Applications";

if(description)
{
 script_id(11138);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5817);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Citrix published applications";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary;


 script_description(desc);

 summary = "Find Citrix published applications";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2002 John Lampe...j_lampe@bellsouth.net");
 script_family("General");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}


#script code starts here

port = 1604;
trickmaster =               raw_string(0x20,0x00,0x01,0x30,0x02,0xFD,0xA8,0xE3);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
trickmaster = trickmaster + raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

get_pa =          raw_string(0x2A,0x00,0x01,0x32,0x02,0xFD);
get_pa = get_pa + raw_string(0xa8,0xe3,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x21,0x00);
get_pa = get_pa + raw_string(0x02,0x00,0x00,0x00,0x00,0x00);
get_pa = get_pa + raw_string(0x00,0x00,0x00,0x00,0x00,0x00);

if(!get_udp_port_state(port))exit(0);

soc = open_sock_udp(port);
if (soc) {
    send (socket:soc, data:trickmaster);
    incoming = recv(socket:soc, length:1024);
    close(soc);
    if (incoming) {
	soc = open_sock_udp(port);
        send(socket:soc, data:get_pa);
	incoming = recv(socket:soc, length:1024);
	if(incoming) {
	    mywarning = string("The Citrix server is configured in a way which may allow an external attacker\n");
	    mywarning = string(mywarning, "to enumerate remote services.\n\n");
	    mywarning = string(mywarning, "Solution: see http://sh0dan.org/files/hackingcitrix.txt for more info");
	    security_warning(port:port, data:mywarning, proto:"udp");
	}
    }
}

