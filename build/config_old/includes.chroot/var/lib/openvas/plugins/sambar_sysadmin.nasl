# OpenVAS Vulnerability Test
# $Id: sambar_sysadmin.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Sambar /sysadmin directory 2
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
# Changes by rd : use ereg() insted of ><
#
# Copyright:
# Copyright (C) 2000 Hendrik Scholz
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
tag_summary = "The Sambar webserver is running.
It provides a web interface for configuration purposes.
The admin user has no password and there are some other default users without
passwords.
Everyone could set the HTTP-Root to c:\ and delete your files!

*** this may be a false positive - go to http://the_server/sysadmin/ and
have a look at it by yourself";

tag_solution = "Change the passwords via the webinterface or use a real webserver
 like Apache.";

if(description)
{
 script_id(10416);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2255);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Sambar /sysadmin directory 2";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Sambar webserver installed ?";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");

 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 3135);
 script_require_keys("www/sambar");
 
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:3135);
foreach port (ports)
{
 data = http_get(item:"/sysadmin/dbms/dbms.htm", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
  send(socket:soc, data:data);
  buf = recv_line(socket:soc, length:4096);
  buf2 = http_recv(socket:soc);
  http_close_socket(soc);
  if(egrep(pattern:"[sS]ambar", string:buf))
  {
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 403 ", string:buf))security_warning(port);
  }
 }
}

