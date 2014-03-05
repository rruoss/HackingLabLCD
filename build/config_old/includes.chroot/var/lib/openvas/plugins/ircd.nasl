# OpenVAS Vulnerability Test
# $Id: ircd.nasl 41 2013-11-04 19:00:12Z jan $
# Description: IRC daemon identification
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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
tag_summary = "This script determines the version of the IRC daemon";

if(description)
{
 script_id(11156);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 41 $");
 script_tag(name:"last_modification", value:"$Date: 2013-11-04 20:00:12 +0100 (Mo, 04. Nov 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"risk_factor", value:"None");
 
 name = "IRC daemon identification";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary;

 script_description(desc);
 
 summary = "IRCD version";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "General";
 script_family(family);

 script_dependencies("find_service.nasl", "find_service2.nasl");
 script_require_ports("Services/irc", 6667);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

port = get_kb_item("Services/irc");
if (!port) port = 6667;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

nick = NULL;
for (i=0;i<9;i++)
 nick += raw_string (0x41 + (rand() % 10));

user = nick;

req = string("NICK ", nick, "\r\n", 
	"USER ", nick, " ", this_host_name(), " ", get_host_name(), 
	" :", user, "\r\n");
send(socket: soc, data: req);
while ( a = recv_line(socket:soc, length:4096) )
{
 #display(a);
 if ( a =~ "^PING." )
 {
  a = ereg_replace(pattern:"PING", replace:"PONG", string:a);
  send(socket:soc, data:a);
 }
}

send(socket: soc, data: string("VERSION\r\n"));
v = "x";
while ((v) && ! (" 351 " >< v)) v = recv_line(socket: soc, length: 256);
#display(v);
send(socket: soc, data: string("QUIT\r\n"));
close(soc);

if (!v) exit(0);

k = string("irc/banner/", port);
set_kb_item(name: k, value: v);

# Answer looks like:
# :irc.sysdoor.com 351 nessus123 2.8/csircd-1.13. irc.sysdoor.com :http://www.codestud.com/ircd
v2 = ereg_replace(string: v, pattern: ": *[^ ]+ +[0-9]+ +[a-zA-Z0-9]+ +([^ ]+) +[^ ]+ *:(.*)", replace: "\1 \2");
# display(v2);
if (v == v2) exit(0);

m = string("The IRC server version is : ", v2);
security_note(port: port, data: m);

