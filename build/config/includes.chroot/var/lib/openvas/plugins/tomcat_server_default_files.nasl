# OpenVAS Vulnerability Test
# $Id: tomcat_server_default_files.nasl 17 2013-10-27 14:01:43Z jan $
# Description: Apache Tomcat servlet/JSP container default files
#
# Authors:
# David Kyger <david_kyger@symantec.com>
#
# Copyright:
# Copyright (C) 2004 David Kyger
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
tag_summary = "The Apache Tomcat servlet/JSP container has default files installed.

These files should be removed as they may help an attacker to guess the
exact version of the Apache Tomcat which is running on this host and may 
provide other useful information.";

if(description)
{
  script_id(12085);
  script_version("$Revision: 17 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 15:01:43 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");

 name = "Apache Tomcat servlet/JSP container default files ";
 script_name(name);
 
 desc = "
  Summary:
  " + tag_summary;

 script_description(desc);
 
 summary = "Checks for Apache Tomcat default files ";
 
 script_summary(summary);
 
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2004 David Kyger");
 family = "General";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "summary" , value : tag_summary);
  }
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

warning = string("

Default files, such as documentation, default Servlets and JSPs were found on 
the Apache Tomcat servlet/JSP container.  

Remove default files, example JSPs and Servlets from the Tomcat
Servlet/JSP container.

These files should be removed as they may help an attacker to guess the
exact version of Apache Tomcat which is running on this host and may provide 
other useful information.

The following default files were found :");

port = get_http_port(default:8080);
if (!port) exit(0);

if(get_port_state(port))
 {
  pat1 = "The Jakarta Project";
  pat2 = "Documentation Index";
  pat3 = "Examples with Code";
  pat4 = "Servlet API";
  pat5 = "Snoop Servlet";
  pat6 = "Servlet Name";
  pat7 = "JSP Request Method";
  pat8 = "Servlet path";
  pat9 = "session scoped beans";
  pat9 = "Java Server Pages";
  pat10 = "session scoped beans";
  

  fl[0] = "/tomcat-docs/index.html";
  fl[1] = "/examples/servlets/index.html";
  fl[2] = "/examples/servlet/SnoopServlet";
  fl[3] = "/examples/jsp/snp/snoop.jsp";
  fl[4] = "/examples/jsp/index.html";

  for(i=0;fl[i];i=i+1) {
    req = http_get(item:fl[i], port:port);
    buf = http_keepalive_send_recv(port:port, data:req);
    if ( buf == NULL ) exit(0);
    if ((pat1 >< buf && pat2 >< buf) || (pat3 >< buf && pat4 >< buf) || (pat5 >< buf && pat6 >< buf) || (pat7 >< buf && pat8 >< buf) || (pat9 >< buf && pat10 >< buf)) {
     warning = warning + string("\n", fl[i]);
     flag = 1;
     }
   }
    if (flag > 0) { 
     security_hole(port:port, data:warning);
    }
}
