# OpenVAS Vulnerability Test
# $Id: apache_Tomcat_Servlet_XSS.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Tomcat /servlet Cross Site Scripting
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
tag_solution = "The 'invoker' servlet (mapped to /servlet/), which executes anonymous servlet
classes that have not been defined in a web.xml file should be unmapped.

The entry for this can be found in the /tomcat-install-dir/conf/web.xml file.";

tag_summary = "The remote Apache Tomcat web server is vulnerable to a cross site scripting 
issue.

Description :

Apache Tomcat is the servlet container that is used in the official Reference 
Implementation for the Java Servlet and JavaServer Pages technologies.

By using the /servlet/ mapping to invoke various servlets / classes it is
possible to cause Tomcat to throw an exception, allowing XSS attacks,e.g:

tomcat-server/servlet/org.apache.catalina.servlets.WebdavStatus/SCRIPTalert(document.domain)/SCRIPT
tomcat-server/servlet/org.apache.catalina.ContainerServlet/SCRIPTalert(document.domain)/SCRIPT
tomcat-server/servlet/org.apache.catalina.Context/SCRIPTalert(document.domain)/SCRIPT
tomcat-server/servlet/org.apache.catalina.Globals/SCRIPTalert(document.domain)/SCRIPT

(angle brackets omitted)";


# Also covers BugtraqID: 5194 (same Advisory ID#: wp-02-0008)

if(description)
{
 script_id(11041);
 script_version("$Revision: 17 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(5193);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");
 script_cve_id("CVE-2002-0682");
 
 name = "Apache Tomcat /servlet Cross Site Scripting";
 script_name(name);
 
 desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;


 script_description(desc);
 
 summary = "Tests for Apache Tomcat /servlet XSS Bug";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/apache");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "solution" , value : tag_solution);
 }
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8080);
if(!port)exit(0);

if(!get_port_state(port)) exit(0);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);
sig = get_kb_item("www/hmap/"  + port  + "/description");
if ( sig && "Apache" >!< sig && "Tomcat" >!<  sig ) exit(0);

req = http_get(item:"/servlet/org.apache.catalina.ContainerServlet/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
r = http_keepalive_send_recv(port:port, data:req);
confirmed = string("<SCRIPT>alert(document.domain)</SCRIPT>"); 
confirmed_too = string("javax.servlet.ServletException");
  if ((confirmed >< r) && (confirmed_too >< r)) {
		security_hole(port);
}
