# OpenVAS Vulnerability Test
# $Id: misc_format_string.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Generic format string
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
tag_summary = "The remote service is vulnerable to a format string attack
An attacker may use this flaw to execute arbitrary code on this host.";

tag_solution = "upgrade your software or contact your vendor and inform it of this
vulnerability
";
# References:
# Date:	 Wed, 20 Mar 2002 11:35:04 +0100 (CET)
# From:	"Wojciech Purczynski" <cliph@isec.pl>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org
# CC: security@isec.pl
# Subject: Bypassing libsafe format string protection
# 
# TBD: Add those tests:
#	printf("%'n", &target);
#	printf("%In", &target);
#	printf("%2$n", "unused argument", &target);

if(description)
{
 script_id(11133);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Generic format string";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Generic format string attack";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK); 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Gain a shell remotely";

 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/unknown");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/81565");
 exit(0);
}

#

include('misc_func.inc');

port = get_kb_item("Services/unknown");
if (! port) exit(0);
if ( ! service_is_unknown(port:port) ) exit(0);


if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(0);

send(socket: soc, data: "xxxxxxxxxxxxxxxxxxxxxxxxxx");
r1 = recv(socket: soc, length: 256, min:1);
close(soc);

flag = 1;
if (egrep(pattern:"[0-9a-fA-F]{4}", string: r1)) flag = 0;



soc = open_sock_tcp(port);
if (! soc) exit(0);
send(socket: soc, 
	data: crap(data:"%#0123456x%04x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%04x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%04x",
		length:256) );
r2 = recv(socket: soc, length: 256, min:1);
close(soc);


soc = open_sock_tcp(port);
if (! soc)
{
  security_hole(port);
  exit(0);
}

close(soc);

if (flag && (egrep(pattern:"[0-9a-fA-F]{4}", string: r2)))
{
  security_warning(port);
  exit(0);
}



