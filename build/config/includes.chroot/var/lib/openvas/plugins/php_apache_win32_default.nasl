# OpenVAS Vulnerability Test
# $Id: php_apache_win32_default.nasl 17 2013-10-27 14:01:43Z jan $
# Description: PHP.EXE / Apache Win32 Arbitrary File Reading Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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
tag_summary = "A configuration vulnerability exists for PHP.EXE cgi running on Apache 
for Win32 platforms. It is reported that the installation text recommends 
configuration options in httpd.conf that create a security vulnerability, 
allowing arbitrary files to be read from the host running PHP. Remote users 
can directly execute the PHP binary:

http://www.somehost.com/php/php.exe?c:\winnt\win.ini";

tag_solution = "Obtain the latest version from http://www.php.net";

if(description)
{
 script_id(10839);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-2029");
 script_bugtraq_id(3786);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 name = "PHP.EXE / Apache Win32 Arbitrary File Reading Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_xref(name : "URL" , value : "http://www.securitytracker.com/alerts/2002/Jan/1003104.html");
 script_xref(name : "URL" , value : "http://www.php.net");

 script_description(desc);
 
 summary = "Tests for PHP.EXE / Apache Win32 Arbitrary File Reading Vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 	      
 if ( ! can_host_php(port:port) ) exit(0);
 req = http_get(item:"/php/php.exe?c:\winnt\win.ini", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("[windows]" >< r)	
 	security_hole(port);

 }
}
