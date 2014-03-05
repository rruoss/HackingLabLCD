# OpenVAS Vulnerability Test
# $Id: apache_Tomcat_TroubleShooter.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Tomcat TroubleShooter Servlet Installed
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
tag_summary = "The remote Apache Tomcat Server is vulnerable to cross script scripting and 
path disclosure issues.

Description :

The default installation of Tomcat includes various sample jsp pages and 
servlets.
One of these, the 'TroubleShooter' servlet, discloses various information about 
the system on which Tomcat is installed. This servlet can also be used to 
perform cross-site scripting attacks against third party users.";

tag_solution = "Example files should not be left on production servers.";

if(description)
{
 script_id(11046);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-2006");
 script_bugtraq_id(4575);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 name = "Apache Tomcat TroubleShooter Servlet Installed";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Tests whether the Apache Tomcat TroubleShooter Servlet is installed";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl","http_version.nasl");
 script_require_ports("Services/www", 80, 8080);
 script_require_keys("www/apache");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 script_xref(name : "URL" , value : "http://www.osvdb.org/displayvuln.php?osvdb_id=849");
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(! port || ! get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/"  + port  + "/description");
if ( sig && "Apache" >!< sig && "Tomcat" >!<  sig ) exit(0);

req = http_get(item:"/examples/servlet/TroubleShooter", port:port);
r =   http_keepalive_send_recv(port:port, data:req);
confirmed = string("TroubleShooter Servlet Output"); 
confirmed_too = string("hiddenValue");
if ((confirmed >< r) && (confirmed_too >< r)) 	
	{
 		security_warning(port);
	}
