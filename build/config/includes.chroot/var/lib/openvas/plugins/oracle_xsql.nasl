# OpenVAS Vulnerability Test
# $Id: oracle_xsql.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Oracle XSQL Stylesheet Vulnerability
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2000 Matt Moore
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
tag_summary = "The Oracle XSQL Servlet allows arbitrary Java code to be executed by an attacker by supplying the URL of a malicious XSLT stylesheet when making a request to an XSQL page.";

tag_solution = "Until Oracle changes the default behavior for the XSQL servlet to disallow client supplied stylesheets, you can workaround this problem as follows. Add allow-client-style='no' on the document element of every xsql page on your server.
This plug-in tests for this vulnerability using a sample page, airport.xsql, which is supplied with the Oracle XSQL servlet. Sample code should always be removed from production servers.";

if(description)
{
 script_id(10594);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(2295);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2001-0126");
 name = "Oracle XSQL Stylesheet Vulnerability";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_description(desc);
 
 summary = "Tests for Oracle XSQL Stylesheet Vulnerability";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2000 Matt Moore");
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

# Check starts here
# Check uses a default sample page supplied with the XSQL servlet. 

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{ 
 req = http_get(item:"/xsql/demo/airport/airport.xsql?xml-stylesheet=none", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("cvsroot" >< r)	
 	security_hole(port);

}
