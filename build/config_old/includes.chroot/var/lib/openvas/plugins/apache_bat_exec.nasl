# OpenVAS Vulnerability Test
# $Id: apache_bat_exec.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Remote Command Execution via .bat files
#
# Authors:
# Matt Moore <matt@westpoint.ltd.uk>
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
tag_summary = "The Apache 2.0.x Win32 installation is shipped with a 
default script, /cgi-bin/test-cgi.bat, that allows an attacker to execute 
commands on the Apache server (although it is reported that any .bat file 
could open this vulnerability.)
 
An attacker can send a pipe character with commands appended as parameters, 
which are then executed by Apache.";

tag_solution = "This bug is fixed in 1.3.24 and 2.0.34-beta, or remove /cgi-bin/test-cgi.bat";

if(description)
{
 script_id(10938);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4335);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0061");
 name = "Apache Remote Command Execution via .bat files";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Tests for presence of Apache Command Execution via .bat vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

# Check makes request for cgi-bin/test-cgi.bat?|echo - which should return
# an HTTP 500 error containing the string 'ECHO is on'
# We just check for 'ECHO' (capitalized), as this should remain the same across
# most international versions of Windows(?)

include("http_func.inc");

port = get_http_port(default:80);

if(!get_port_state(port)){ exit(0); }

if ( get_kb_item("Services/www/" + port + "/embedded") ) exit(0);

sig = get_kb_item("www/hmap/" + port + "/description");
if ( sig && "Apache" >!< sig ) exit(0);

soc = http_open_socket(port);
if (!soc) exit(0);

req = http_get(item:"/cgi-bin/test-cgi.bat?|echo", port:port);
send(socket:soc, data:req);
res = http_recv(socket:soc);
http_close_socket(soc);
if ("ECHO" >< res)
{
    security_hole(port:port);
}
