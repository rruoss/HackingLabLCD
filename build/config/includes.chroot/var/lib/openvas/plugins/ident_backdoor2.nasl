# OpenVAS Vulnerability Test
# $Id: ident_backdoor2.nasl 17 2013-10-27 14:01:43Z jan $
# Description: IRC bot detection
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
tag_summary = "This host seems to be running an ident server, but before any 
request is sent, the server gives an answer about a connection 
to port 6667.

It is very likely this system has heen compromised by an IRC 
bot and is now a 'zombi' that can participate into 'distributed 
denial of service' (DDoS).";

tag_solution = "desinfect or re-install your system";

# I'm not sure what this backdoor is...

if(description)
{
 script_id(18392);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_name( "IRC bot detection");
 script_description(desc);
 script_summary( "Fake IDENT server (IRC bot)");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Malware");
 script_require_ports("Services/fake-identd", 113);
 script_dependencies("find_service1.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

# include('misc_func.inc');

regex = '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+';

port = get_kb_item('Services/fake-identd');
if (! port) port = 113;

if (! get_port_state(port)) exit(0);

b = get_kb_item('FindService/tcp/'+port+'/spontaneous');
# if (! b) b = get_unknown_banner(port: port);
if (! b) exit(0);

if (b =~ '^[0-9]+ *, *6667 *: *USERID *: *UNIX *: *[A-Za-z0-9]+')
  security_hole(port);
