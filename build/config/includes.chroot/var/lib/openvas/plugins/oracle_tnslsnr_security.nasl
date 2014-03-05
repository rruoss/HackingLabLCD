# OpenVAS Vulnerability Test
# $Id: oracle_tnslsnr_security.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle tnslsnr security
#
# Authors:
# James W. Abendschan <jwa@jammed.com>
#
# Copyright:
# Copyright (C) 2001 James W. Abendschan <jwa@jammed.com>
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
tag_solution = "use the lsnrctrl SET PASSWORD command to assign a password to, the tnslsnr.";
tag_summary = "The remote Oracle tnslsnr has no password assigned.
An attacker may use this fact to shut it down arbitrarily,
thus preventing legitimate users from using it properly.";


# oracle_tnslsnr_security.nasl - NASL script to do a TNS STATUS 
# command against the Oracle tnslsnr and grep out "SECURITY=OFF"

if (description)
{
	script_id(10660);
	script_version("$Revision: 17 $");
	script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
	script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
	script_name( "Oracle tnslsnr security");
  desc = "
  Summary:
  " + tag_summary + "
 Solution:
 " + tag_solution;

	script_summary( "Determines if the Oracle tnslsnr has been assigned a password.");
  script_description(desc);

	script_category(ACT_GATHER_INFO);
	script_family("General");
	script_copyright("Copyright (C) 2001 James W. Abendschan <jwa@jammed.com>");
	script_dependencies("oracle_tnslsnr_version.nasl");
        script_require_ports("Services/oracle_tnslsnr");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
	exit(0);
}

function tnscmd(sock, command)
{
	# construct packet
	
	command_length = strlen(command);
	packet_length = command_length + 58;

	# packet length - bytes 1 and 2

	plen_h = packet_length / 256;
	plen_l = 256 * plen_h;			# bah, no ( ) ?
	plen_l = packet_length - plen_h;

	clen_h = command_length / 256;
	clen_l = 256 * clen_h;
	clen_l = command_length - clen_l;


	packet = raw_string(
		plen_h, plen_l, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 
		0x01, 0x36, 0x01, 0x2c, 0x00, 0x00, 0x08, 0x00, 
		0x7f, 0xff, 0x7f, 0x08, 0x00, 0x00, 0x00, 0x01, 
		clen_h, clen_l, 0x00, 0x3a, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x34, 0xe6, 0x00, 0x00, 
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, command
		);


	send (socket:sock, data:packet);
	r = recv(socket:sock, length:8192, timeout:5);

	return (r);
}


function oracle_tnslsnr_security(port)
{
	sock = open_sock_tcp(port);
	if (sock) 
	{
		cmd = "(CONNECT_DATA=(COMMAND=STATUS))";
		reply = tnscmd(sock:sock, command:cmd);
		close(sock);
		if ( ! reply ) return 0;

		if ("SECURITY=OFF" >< reply)
		{
			security_warning(port:port);
		}
		else
		{
			if ("SECURITY=ON" >< reply)
			{
				# FYI
				report = string
				(
				"This host is running a passworded Oracle tnslsnr.\n"
				);
				security_note(port:port, data:report);
			}
		} 
	}	
}

# tnslsnr runs on different ports . . .

port = get_kb_item("Services/oracle_tnslsnr");
if ( isnull(port)) exit(0);

if(get_port_state(port))
 {
  oracle_tnslsnr_security(port:port);
 }

