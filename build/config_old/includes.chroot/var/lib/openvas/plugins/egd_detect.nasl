# OpenVAS Vulnerability Test
# $Id: egd_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: EGD detection
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
tag_summary = "A random number generator is listening on the remote port.

Description :

The Entropy Gathering Daemon is running on the remote host.
EGD is a user space random generator for operating systems 
that lack /dev/random";

tag_solution = "If this service is not needed, disable it or filter incoming traffic
to this port.";

if(description)
{
 script_id(18393);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_name( "EGD detection");
 script_description(desc);
 script_summary( "Detect the Entropy Gathering Daemon (EGD)");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Service detection");
 script_require_ports("Services/unknown");
 script_dependencies("find_service1.nasl", "find_service2.nasl");
 script_require_keys("Settings/ThoroughTests");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://egd.sourceforge.net/");
 exit(0);
}

#
include('global_settings.inc');
include('misc_func.inc');

if ( ! thorough_tests ) exit(0);

port = get_kb_item("Services/unknown");
if (! get_port_state(port)) exit(0);
if (! service_is_unknown(port:port) ) exit(0);

if (get_kb_item('FindService/tcp/'+port+'/spontaneous') ||
    get_kb_item('FindService/tcp/'+port+'/get_http') ||
    get_kb_item('FindService/tcp/'+port+'/help') )
 exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\0');	# get
r = recv(socket: s, length: 16);
close(s);
if (strlen(r) != 4) exit(0);
entropy = 0;
for (i = 0; i <= 3; i ++)
 entropy = (entropy << 8) | ord(r[i]);

debug_print('entropy=', entropy, '\n');

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\x01\x07');	# Read 7 bytes of entropy
r = recv(socket: s, length: 16);
close(s);
n = ord(r[0]);
if (strlen(r) != n + 1) exit(0);
debug_print('EGD gave ', n, 'bytes of entropy (7 requested)\n');

register_service(port: port, proto: 'egd');
security_note(port);
