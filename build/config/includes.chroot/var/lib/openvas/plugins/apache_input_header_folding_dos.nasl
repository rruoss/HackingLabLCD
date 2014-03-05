# OpenVAS Vulnerability Test
# $Id: apache_input_header_folding_dos.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Input Header Folding and mod_ssl ssl_io_filter_cleanup DoS Vulnerabilities
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
tag_summary = "The remote host appears to be running a version of Apache 2.x which is
older than 2.0.50. 

There is denial of service in apache httpd 2.0.x by sending a
specially crafted HTTP request.  It is possible to consume arbitrary
amount of memory.  On 64 bit systems with more than 4GB virtual memory
this may lead to heap based buffer overflow.  See also
http://www.guninski.com/httpd1.html

There is also a denial of service vulnerability in mod_ssl's
ssl_io_filter_cleanup function.  By sending a request to vulnerable
server over SSL and closing the connection before the server can send
a response, an attacker can cause a memory violation that crashes the
server.";

tag_solution = "Upgrade to Apache/2.0.50 or newer";

#ref: Georgi Guninski (June 2004)

if(description)
{
 script_id(12293);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(10619, 12877);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2004-0493");
 script_xref(name:"OSVDB", value:"7269");
  
 name = "Apache Input Header Folding and mod_ssl ssl_io_filter_cleanup DoS Vulnerabilities";

 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;

 script_description(desc);
 
 summary = "Checks for version of Apache";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Denial of Service";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_keys("www/apache");
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
include("backport.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);
 
if(egrep(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/2\.0\.(([0-9][^0-9])([0-3][0-9][^0-9])|(4[0-9][^0-9])).*", string:banner))
 {
   security_hole(port);
 }
}
