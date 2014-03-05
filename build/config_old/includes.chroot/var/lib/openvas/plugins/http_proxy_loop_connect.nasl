# OpenVAS Vulnerability Test
# $Id: http_proxy_loop_connect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Proxy accepts CONNECT requests to itself
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
tag_summary = "The proxy allows the users to perform
repeated CONNECT requests to itself.

This allow anybody to saturate the proxy CPU, memory or 
file descriptors.

** Note that if the proxy limits the number of connections
** from a single IP (e.g. acl maxconn with Squid), it is 
** protected against saturation and you may ignore this alert.";

tag_solution = "reconfigure your proxy so that
          it refuses CONNECT requests to itself.";

if(description)
{ 
 script_id(17154);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 
 name = "Proxy accepts CONNECT requests to itself";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Connects back to the web proxy through itself"; 
 script_summary(summary);

 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 
 family = "Denial of Service"; 
 
 script_family(family);
 script_dependencies("find_service.nasl", "proxy_use.nasl");
 script_require_keys("Proxy/usage");
 script_require_ports("Services/http_proxy", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

port = get_kb_item("Services/http_proxy");
if (!port) port = 8080;
if (! COMMAND_LINE)
{
 proxy_use = get_kb_item("Proxy/usage");
 if (! proxy_use) exit(0);
}
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

cmd = strcat('CONNECT ', get_host_name(), ':', port, ' HTTP/1.0\r\n\r\n');
for (i = 3; i >= 0; i --)
{
 send(socket:soc, data: cmd);
 repeat 
  line = recv_line(socket:soc, length:4096);
 until (! line || line =~ '^HTTP/[0-9.]+ ');
 if (line !~ '^HTTP/[0-9.]+ +200 ') break;	# Also exit loop on EOF
}

close(soc);
if (i < 0) security_hole(port);
