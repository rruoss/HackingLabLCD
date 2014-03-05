# OpenVAS Vulnerability Test
# $Id: tetrinet_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Tetrinet server detection
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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
tag_summary = "A game server has been detected on the remote host.


Description :

The remote host runs a Tetrinet game server on this port. Make
sure the use of this software is done in accordance to your
security policy.";

tag_solution = "If this service is not needed, disable it or filter incoming 
traffic to this port.";

if(description)
{
 script_id(19608);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 script_name( "Tetrinet server detection");
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 script_summary( "Detect Tetrinet game server");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Service detection");
 script_require_ports("Services/unknown", 31457);
 script_dependencies("find_service.nasl", "find_service2.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

########

include("misc_func.inc");
include("global_settings.inc");

c = '00469F2CAA22A72F9BC80DB3E766E7286C968E8B8FF212\xff';
if (thorough_tests)
 port = get_kb_item("Services/unknown");
else
 port = 31457;
if (! get_port_state(port) || ! service_is_unknown(port: port)) exit(0);

s = open_sock_tcp(port);
if (!s) exit(0);

send(socket: s, data:c);
b = recv(socket: s, length: 1024);
if ( ! b ) exit(0);
if (match(string: b, pattern: 'winlist *'))
{
 security_note(port: port);
 register_service(port: port, proto: 'tetrinet');
}
