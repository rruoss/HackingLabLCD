# OpenVAS Vulnerability Test
# $Id: xot_detect.nasl 16 2013-10-27 13:09:52Z jan $
# Description: XOT Detection
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2008 Michel Arboi
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
tag_summary = "This plugin detects XOT (X.25 over TCP).

The remote target is an XOT router.
For more information, read RFC 1613 or
http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/x25.pdf";

if (description)
{
 script_id(80095);;
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name( "XOT Detection");
 desc = "
 Summary:
 " + tag_summary;
 script_description(desc);
 script_summary( 'Detect XOT by sending an invalid packet');
 script_copyright( 'This script is Copyright (C) 2008 Michel Arboi');
 script_dependencies('find_service1.nasl', 'find_service2.nasl');
 script_category(ACT_GATHER_INFO);
 script_family( "Service detection");
 script_require_ports(1998, "Services/unknown");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# include('dump.inc');
include('misc_func.inc');
include('global_settings.inc');

if ( get_kb_item("global_settings/disable_service_discovery")) exit(0);
port = 1998;

if (! get_port_state(port)) exit(0);

# XOT is not silent: it abruptly closes the connection when it receives
# invalid data
#if (silent_service(port)) exit(0);

# By the way, GET and HELP are definitely invalid. So...
b = get_unknown_banner(port: port, dontfetch: 1);
if (strlen(b) > 0) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);
x25 = '\x20'		# Data for user, local ack, mod-128 seq
      			# LGCN = 0
    + '\0'		# LCN = 0 (reserved => invalid)
    + '\0'		# Data packet
    + '\0\0\0\0';	# Data

# XOT encapsulation (RFC 1613): 
# 2 bytes for version (must be 0) + 2 bytes for length of X25 packet
len = strlen(x25);
xot = raw_string(0, 0, (len >> 8), (len & 0xFF));

send(socket: soc, data: xot + x25);
# t1 = unixtime();
r = recv(socket: soc, length: 512);
# t2 = unixtime();
close(soc);
# dump(dtitle: 'XOT', ddata: r);
lenxot = strlen(r);
if (lenxot < 4) exit(0);
if (r[0] != '\0' || r[1] != '\0') exit(0);
lenx25 = (ord(r[2]) << 8) | ord(r[3]);
if (lenx25 + 4 != lenxot) exit(0);
register_service(port: port, proto: 'xot');
security_note(port);
