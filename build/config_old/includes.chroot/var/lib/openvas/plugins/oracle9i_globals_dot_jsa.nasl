# OpenVAS Vulnerability Test
# $Id: oracle9i_globals_dot_jsa.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle 9iAS Globals.jsa access
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
tag_summary = "In the default configuration of Oracle9iAS, it is possible to make 
requests for the globals.jsa file for a given web application. 
These files should not be returned by the server as they often 
contain sensitive information.";

tag_solution = "Edit httpd.conf to disallow access to *.jsa.";

if(description)
{
 script_id(10850);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4034);
 script_cve_id("CVE-2002-0562");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Oracle 9iAS Globals.jsa access";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.nextgenss.com/advisories/orajsa.txt");
 script_xref(name : "URL" , value : "http://www.oracle.com");

 script_description(desc);
 
 summary = "Tests for Oracle9iAS Globals.jsa access";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
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
# Make a request for one of the demo files .jsa files. This can be 
# improved to use the output of webmirror.nasl, allowing the plugin to
# test for this problem in configurations where the demo files have
# been removed.

 req = http_get(item:"/demo/ojspext/events/globals.jsa",
 		port:port); 
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("event:application_OnStart" >< r)	
 	security_warning(port);

 }
}
