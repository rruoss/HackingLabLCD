# OpenVAS Vulnerability Test
# $Id: socks5_loop_connect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Connect back to SOCKS5 server
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
tag_summary = "It was possible to connect to the SOCKS5 server
through itself. 
This allow anybody to saturate the proxy CPU, memory or 
file descriptors.";

tag_solution = "reconfigure your proxy so that it refuses connections to itself";

# Socks5 is defined by those RFC:
# RFC1928 SOCKS Protocol Version 5
# RFC1929 Username/Password Authentication for SOCKS V5
# RFC1961 GSS-API Authentication Method for SOCKS Version 5

if(description)
{
 script_id(17156);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "Connect back to SOCKS5 server";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Connect back to SOCKS5 proxy";
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_ports("Services/socks5", 1080);
 script_dependencies("find_service.nasl", "find_service2.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

# include("dump.inc");

port = get_kb_item("Services/socks5");
if (! port) port = 1080;
if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit(0);

req5 = raw_string(5, 3, 0, 1, 2);
send(socket: s, data: req5);
data = recv(socket: s, length: 2);

p2 = port % 256;
p1 = port / 256;
a = split(get_host_ip(), sep: '.');

cmd = 
raw_string(5, 1, 0, 1, int(a[0]), int(a[1]), int(a[2]), int(a[3]), p1, p2);

for (i = 3; i >= 0; i --)
{
  send(socket: s, data: cmd);
  data = recv(socket: s, length: 10, min: 10);
# dump(ddata: data, dtitle: "socks");
  if (strlen(data) != 10 || ord(data[0]) != 5 || ord(data[1]) != 0) break;
}

close(s);
if (i < 0) security_hole(port);

