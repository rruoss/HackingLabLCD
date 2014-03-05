# OpenVAS Vulnerability Test
# $Id: iax2_detection.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Inter-Asterisk eXchange Protocol Detection
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
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
tag_summary = "The remote system is running a server that speaks the Inter-Asterisk
eXchange Protocol. 

Description :

The Inter-Asterisk eXchange protocol (IAX2) is used by the Asterisk
PBX Server and other IP Telephony clients/servers to enable voice
communication between them.";

tag_solution = "If possible, filter incoming connections to the port so that it is
used by trusted sources only.";

if (description) {
script_id(20834);
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
script_tag(name:"cvss_base", value:"0.0");
script_tag(name:"risk_factor", value:"None");

name = "Inter-Asterisk eXchange Protocol Detection";
script_name(name);

desc = "
Summary:
" + tag_summary + "
Solution:
" + tag_solution;
script_description(desc);

summary = "Checks if the remote system is running the IAX2 protocol";
script_summary(summary);

script_category(ACT_GATHER_INFO);
script_family("Service detection");
script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");
script_require_udp_ports(4569);
if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
}
script_xref(name : "URL" , value : "http://en.wikipedia.org/wiki/IAX");
exit(0);
}

include("misc_func.inc");

port = 4569;
if (!get_udp_port_state(port)) exit(0);

# Open the socket but don't check the state of it.
soc = open_sock_udp(port);

# Generate the 'IAX2' poke packet.
poke_msg = raw_string(
        0x80, 0x00,		# IAX2 Full Packet Type
        0x00, 0x00,		# Destination Call
        0x00, 0x00, 0x00, 0x00,	# Timestamp
        0x00,               	# Outbound Seq No
        0x00,                   # Inbound Seq No
        0x06,                   # IAX Type
        0x1E);                  # IAX2 Poke Command

# Send the poke request.
send(socket:soc, data:poke_msg);

recv = recv(socket:soc, length:128);
if (recv == NULL) exit(0);

# Check if we get the right response. 
if (strlen(recv) != 12) exit(0);
if (ord(recv[10]) == 6 && 	# IAX Type 
   (ord(recv[11]) == 3 || 	# IAX PONG 
    ord(recv[11]) == 4))  {	# IAX ACK
  
 security_note(port);
 register_service(ipproto:"udp", proto:"iax2", port:port);
 exit(0);
}