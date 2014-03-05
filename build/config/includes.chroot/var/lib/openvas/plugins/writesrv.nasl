# OpenVAS Vulnerability Test
# $Id: writesrv.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Writesrv
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
tag_summary = "writesrv is running on this port; it is used to send messages 
to users.
This service gives potential attackers information about who
is connected and who isn't, easing social engineering attacks for
example.";

tag_solution = "disable this service if you don't use it";

if(description)
{
  script_id(11222);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
 
  name = "Writesrv";
  script_name(name);
 
  desc = "
  Summary:
  " + tag_summary + "
  Solution:
  " + tag_solution;

 script_description(desc);
 
 summary = "Detect writesrv";
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("Copyright (C) 2003 Michel Arboi");
 family = "Useless services";
 script_family(family);
 script_dependencies("find_service.nasl");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}

# port = get_kb_item("Services/unknown");
port = 2401;	# Yes! Just like cvspserver!

if (! get_port_state(port)) exit(0);

s = open_sock_tcp(port);
if (! s) exit (0);

m1 = "OPENVAS" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
l0 = raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
m2 = "root" + raw_string(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

m = m1 + l0;
for (i=2; i < 32; i=i+1) m = m + l0;
m = m + m2;
for (i=2; i < 32; i=i+1) m = m + l0;

m = m + raw_string(0x2e, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, l0);
#display(m) ; exit(0);
send(socket: s, data: m);
r = recv(socket: s, length: 1536);
#display(r);

len = strlen(r);
if (len < 512) exit(0);	# Can 'magic read' break this?

# It seems that the answer is split into 512-bytes blocks padded 
# with nul bytes:
# <digit> <space> <digit> <enough bytes...>
# Then, if the user is logged:
# <ttyname> <nul bytes...>
# And maybe another block
# <tty2name> <nul bytes...>

for (i = 16; i < 512; i = i + 1)
{
  if (ord(r[i]) != 0) exit(0);
}

security_warning(port);
