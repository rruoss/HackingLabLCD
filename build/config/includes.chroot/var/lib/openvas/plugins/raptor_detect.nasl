# OpenVAS Vulnerability Test
# $Id: raptor_detect.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Raptor FW version 6.5 detection
#
# Authors:
# Noam Rathaus
# Holm Diening / SLITE IT-Security (holm.diening@slite.de)
#
# Copyright:
# Copyright (C) 2000 Holm Diening
# Copyright (C) 2001 Holm Diening / SLITE IT-Security (holm.diening@slite.de)
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
tag_summary = "By sending an invalid HTTP request to an
 webserver behind Raptor firewall, the http
 proxy itself will respond.

 The server banner of Raptor FW version 6.5
 is always 'Simple, Secure Web Server 1.1'

 You should avoid giving an attacker such
 information.";

tag_solution = "patch httpd / httpd.exe by hand";

if(description)
{
 script_id(10730);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Raptor FW version 6.5 detection";

 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "Checks if the remote host is protected by Raptor FW 6.5";

 script_summary(summary);

 script_category(ACT_GATHER_INFO);


 script_copyright("This script is Copyright (C) 2000 Holm Diening");
 family = "Firewalls";

 script_family(family);

 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
port = get_http_port(default:80);


if(get_port_state(port))
{
 socwww = open_sock_tcp(port);

 if (socwww)
  {
   teststring = string("some invalid request\r\n\r\n");
   testpattern = string("Simple, Secure Web Server 1.");
   send(socket:socwww, data:teststring);
   recv = http_recv(socket:socwww);
   if (testpattern >< recv)
   {
    report = string("The remote WWW host is very likely behind Raptor FW Version 6.5\n", "You should patch the httpd proxy to return bogus version and stop\n", "the information leak\n");
    security_note(port:port, data:report);
    set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
   }
  close(socwww);
  }
 }
