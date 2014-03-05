# OpenVAS Vulnerability Test
# $Id: DDI_PIX_Firewall_Manager.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PIX Firewall Manager Directory Traversal
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID and CVE
#
# Copyright:
# Copyright (C) 2001 Digital Defense Inc.
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
tag_summary = "It is possible to read arbitrary files on the remote host
through the remote web server.

Description :

It is possible to read arbitrary files on this machine by using
relative paths in the URL. This flaw can be used to bypass the
management software's password protection and possibly retrieve
the enable password for the Cisco PIX.

This vulnerability has been assigned Cisco Bug ID: CSCdk39378.";

tag_solution = "Cisco originally recommended upgrading to version 4.1.6b or version 
4.2, however the same vulnerability has been found in version 4.3. 
Cisco now recommends that you disable the software completely and 
migrate to the new PIX Device Manager software.";

if(description)
{
 script_id(10819);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(691);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-1999-0158");

 name = "PIX Firewall Manager Directory Traversal";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);

 summary = "\..\..\file.txt";
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2001 Digital Defense Inc.");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8181);
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
include("http_keepalive.inc");
include("misc_func.inc");


ports = add_port_in_list(list:get_kb_list("Services/www"), port:8181);
ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);

foreach port (ports)
{
    req = http_get(item:string("/..\\pixfir~1\\how_to_login.html"), port:port);
    r   = http_keepalive_send_recv(port:port, data:req);
    if(r && "How to login" >< r) security_warning(port);
}
