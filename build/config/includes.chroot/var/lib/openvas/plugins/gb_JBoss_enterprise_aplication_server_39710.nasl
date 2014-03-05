###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_JBoss_enterprise_aplication_server_39710.nasl 14 2013-10-27 12:33:37Z jan $
#
# JBoss Enterprise Application Platform Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
tag_summary = "JBoss Enterprise Application Platform is prone to multiple
vulnerabilities, including an information-disclosure issue and
multiple authentication-bypass issues.

An attacker can exploit these issues to bypass certain security
restrictions to obtain sensitive information or gain unauthorized
access to the application.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_id(100610);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-04-28 14:05:27 +0200 (Wed, 28 Apr 2010)");
 script_bugtraq_id(39710);
 script_cve_id("CVE-2010-0738","CVE-2010-1428","CVE-2010-1429");

 script_name("JBoss Enterprise Application Platform Multiple Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39710");
 script_xref(name : "URL" , value : "http://www.jboss.org");

 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"risk_factor", value:"Medium");
 script_description(desc);
 script_summary("Determine if remote JBoss Enterprise Application server version is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("JBoss_enterprise_aplication_server_detect.nasl");
 script_require_ports("Services/www", 8080);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!get_port_state(port))exit(0);

if(!vers = get_kb_item(string("www/", port,"/jboss_enterprise_application_server")))exit(0);

url = "/jmx-console";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL ) exit(0);

if(buf =~ "HTTP/1.. [2|3]00")exit(0);

url = "/jmx-console/checkJNDI.jsp";
host = get_host_name();

req = string(
	     "PUT ", url, " HTTP/1.0\r\n",
	     "Host: ", host, "\r\n",
	     "\r\n"
	     );

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( result =~ "HTTP/1.. 200" && ("JNDI Check</title>" >< result  && "JNDI Checking for host" >< result)) {

  security_warning(port:port);
  exit(0);

}  

url = "/status?full=true";
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL ) exit(0);

if("<title>Tomcat Status</title>" >< buf && "Application list" >< buf && "Processing time:" >< buf) {

  security_warning(port:port);
  exit(0);

}  

exit(0);
