###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_jboss_tomcat_62854.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apache Tomcat/JBoss EJBInvokerServlet / JMXInvokerServlet (RMI over HTTP) Marshalled Object Remote Code Execution
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103811";

tag_insight = "The specific flaw exists within the exposed EJBInvokerServlet and
JMXInvokerServlet. An unauthenticated attacker can post a marshalled object allowing
them to install an arbitrary application on the target server.";

tag_impact = "Successfully exploiting these issues may allow an attacker to execute
arbitrary code within the context of the affected application. Failed
exploit attempts may result in a denial-of-service condition.";

tag_affected = "Apache Tomcat/JBoss Application Server";

tag_summary = "Apache Tomcat/JBoss Application Server is prone to multiple remote code-
execution vulnerabilities.";

tag_solution = "Ask the Vendor for an update.";
tag_vuldetect = "Determine if EJBInvokerServlet/JMXInvokerServlet accessible without authentication.";

if (description)
{
 script_oid(SCRIPT_OID);
 script_bugtraq_id(62854);
 script_version ("$Revision: 11 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("Apache Tomcat/JBoss EJBInvokerServlet / JMXInvokerServlet (RMI over HTTP) Marshalled Object Remote Code Execution");

 desc = "
Summary:
" + tag_summary + "

Vulnerability Detection:
" + tag_vuldetect + "

Vulnerability Insight:
" + tag_insight + "

Impact:
" + tag_impact + "

Affected Software/OS:
" + tag_affected + "

Solution:
" + tag_solution;

 script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62854");
 
 script_tag(name:"risk_factor", value:"Critical");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
 script_tag(name:"creation_date", value:"2013-10-15 10:27:36 +0200 (Tue, 15 Oct 2013)");
 script_description(desc);
 script_summary(tag_vuldetect);
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port(default:9200);

files = make_list("/EJBInvokerServlet", "/JMXInvokerServlet");

foreach file (files) {

  url = '/invoker' + file;
  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if(buf =~ "HTTP/1.. 200" && 
     "404" >!< buf &&
     "org.jboss.invocation.MarshalledValue" >< buf &&
     "x-java-serialized-object" >< buf &&
     "WWW-Authenticate" >!< buf) {

    security_hole(port:port);
    exit(0);

  }  

}  

exit(0);

