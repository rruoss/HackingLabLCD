# OpenVAS Vulnerability Test
# $Id: netop_detect_tcp.nasl 17 2013-10-27 14:01:43Z jan $
# Description: NetOp products TCP detection
#
# Authors:
# Martin O'Neal of Corsaire (http://www.corsaire.com)  
# Jakob Bohm of Danware (http://www.danware.dk)
#
# Copyright:
# Copyright (C) 2004 Corsaire Limited and Danware Data A/S
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
tag_summary = "This script detects if the remote system has a Danware NetOp
program enabled and running on TCP.  These programs are used
for remote system administration, for telecommuting and for
live online training and usually allow authenticated users to
access the local system remotely.

Specific information will be given depending on the program
detected";

# declare description
if(description)
{
	script_id(15765);
	script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
    script_tag(name:"cvss_base", value:"0.0");
    script_tag(name:"risk_factor", value:"None");
    name="NetOp products TCP detection";
	script_name(name);

	desc = "
 Summary:
 " + tag_summary;


	script_description(desc);
	summary= "Determines if the remote host has any Danware NetOp program active on TCP";
	script_summary(summary);
	script_category(ACT_GATHER_INFO);
	script_copyright("This NASL script is Copyright 2004 Corsaire Limited and Danware Data A/S.");
	script_family("Service detection");
	script_dependencies("find_service.nasl","find_service2.nasl");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}



############## declarations ################

# includes
include('netop.inc');
include('global_settings.inc');

# declare function
function test(port)
{
	if ( ! get_port_state(port) ) return 0;

	# open connection
	socket=open_sock_tcp(port, transport:ENCAPS_IP);
	
	# check that connection succeeded
	if(socket)
	{
		########## packet one of two ##########
		
		# send packet
		send(socket:socket, data:helo_pkt_gen);
	
		# recieve response
		banner_pkt = recv(socket:socket, length:1500, timeout: 3);
		
		# check response contains correct contents and
		#   log response accordingly.
		
		netop_check_and_add_banner();
		
		########## packet two of two ##########
		
		if (ord(netop_kb_val[39]) == 0xF8)
		{
			send(socket:socket,data:quit_pkt_stream);
		}
		close(socket);
	}
}


############## script ################

# initialise variables
local_var socket;
addr=get_host_ip();
proto_nam='tcp';

# test default ports
test(port:6502);
test(port:1971);

if ( thorough_tests )
{
# retrieve and test unknown services
port=get_kb_item("Services/unknown");
if(!port)exit(0);
if(!get_tcp_port_state(port))exit(0);
if(! service_is_unknown(port:port))exit(0);
test(port:port);
}
exit(0);



############## End of TCP-specific detection script ################
