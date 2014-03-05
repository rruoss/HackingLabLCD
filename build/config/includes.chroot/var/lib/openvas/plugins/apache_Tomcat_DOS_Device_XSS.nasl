# OpenVAS Vulnerability Test
# $Id: apache_Tomcat_DOS_Device_XSS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Tomcat DOS Device Name XSS
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added BugtraqID
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
tag_summary = "The remote Apache Tomcat web server is vulnerable to a cross site scripting 
issue.


Description :

Apache Tomcat is the servlet container that is used in the official Reference 
Implementation for the Java Servlet and JavaServer Pages technologies.

By making requests for DOS Device names it is possible to cause
Tomcat to throw an exception, allowing XSS attacks, e.g:

tomcat-server/COM2.IMG%20src='Javascript:alert(document.domain)'

(angle brackets omitted)

The exception also reveals the physical path of the Tomcat installation.";

tag_solution = "Upgrade to Apache Tomcat v4.1.3 beta or later.";

# Also covers BugtraqID: 5193 (same Advisory ID#: wp-02-0008)

if(description)
{
 script_id(11042);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5194);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Apache Tomcat DOS Device Name XSS";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Tests for Apache Tomcat DOS Device name XSS Bug";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.westpoint.ltd.uk/advisories/wp-02-0008.txt");
 exit(0);
}

# Check starts here

include("http_func.inc");

port = get_http_port(default:8080);
if(!port || !get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);


banner = get_http_banner(port:port);

if (!egrep(pattern:"^Server: .*Tomcat/([0-3]\.|4\.0|4\.1\.[0-2][^0-9])", string:banner) ) exit(0);

req = http_get(item:"/COM2.<IMG%20SRC='JavaScript:alert(document.domain)'>", port:port);
soc = http_open_socket(port);
if(soc)
{ 
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 confirmed = string("JavaScript:alert(document.domain)"); 
 confirmed_too = string("java.io.FileNotFoundException");
 if ((confirmed >< r) && (confirmed_too >< r)) 	
	{
 		security_warning(port);
	}
}
