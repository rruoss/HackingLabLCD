# OpenVAS Vulnerability Test
# $Id: sglmerchant_information_disclosure.nasl 17 2013-10-27 14:01:43Z jan $
# Description: sglMerchant Information Disclosure Vulnerability
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 Noam Rathaus <noamr@securiteam.com>
# Copyright (C) 2001 SecuriTeam
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
tag_summary = "A CGI (view_item) that is a part of sglMerchant is installed.

This CGI suffers from a security vulnerability that makes it possible to escape
the bounding HTML root directory and read arbitrary system files.";

tag_solution = "Contact the author of the program

Additional information:
http://www.securiteam.com/unixfocus/5KP012K5FK.html";


if(description)
{
 script_id(10770);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3309);
script_cve_id("CVE-2001-1019");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");

 name = "sglMerchant Information Disclosure Vulnerability";
 script_name(name);

 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);

 summary = "sglMerchant Information Disclosure Vulnerability";
 script_summary(summary);

 script_category(ACT_GATHER_INFO);

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "Web application abuses";
 script_family(family);

 script_dependencies("find_service.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
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

function check(url)
{
 url = string(url, "/view_item?HTML_FILE=../../../../../../../../../../etc/passwd%00");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req);
 if( buf == NULL ) exit(0);
 if (egrep(pattern:".*root:.*:0:[01]:.*", string:buf))
 {
  security_warning(port:port);
  exit(0);
 }
}

port = get_http_port(default:80);


if(get_port_state(port))
{
 check(url:"/cgi_local");
 check(url:"/cgi-local");
 check(url:"/cgi-shop");
 foreach dir (cgi_dirs())
 {
 check(url:dir);
 }
}
