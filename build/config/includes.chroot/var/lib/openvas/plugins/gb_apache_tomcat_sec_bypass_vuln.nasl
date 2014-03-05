###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_sec_bypass_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Apache Tomcat RemoteFilterValve Security Bypass Vulnerability
#
# Authors:      Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful attempt could lead to remote code execution and attacker
  can gain access to context of the filtered value.
  Impact Level: Application";
tag_affected = "Apache Tomcat version 4.1.x - 4.1.31, and 5.5.0";
tag_insight = "Flaw in the application is due to the synchronisation problem when checking
  IP addresses. This could allow user from a non permitted IP address to gain
  access to a context that is protected with a valve that extends
  RemoteFilterValve including the standard RemoteAddrValve and RemoteHostValve
  implementations.";
tag_solution = "Upgrade to Apache Tomcat version 4.1.32, or 5.5.1, or later,
  http://archive.apache.org/dist/tomcat/";
tag_summary = "Apache Tomcat Server is running on this host and that is prone to
  security bypass vulnerability.";

if(description)
{
  script_id(800024);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-16 18:25:33 +0200 (Thu, 16 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-3271");
  script_bugtraq_id(31698);
  script_name("Apache Tomcat RemoteFilterValve Security Bypass Vulnerability");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-4.html");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html");
  script_xref(name : "URL" , value : "https://issues.apache.org/bugzilla/show_bug.cgi?id=25835");

  script_description(desc);
  script_summary("Check for the version of Apache Tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:8080);
if(!port){
  port = 8080;
}
sndReq = http_get(item:string("/index.jsp"), port:port);
rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
if(rcvRes == NULL){
  exit(0);
}

if(egrep(pattern:"<title>Apache Tomcat", string:rcvRes))
{
  rcvRes = eregmatch(pattern:"Apache Tomcat\/([0-9.]+)", string:rcvRes);
  if(rcvRes == NULL){
     exit(0);
  }
  # Apache Tomcat 4.1.0 - 4.1.31, and 5.5.0
  if(version_in_range(version:rcvRes[1], test_version:"4.1", test_version2:"4.1.31") ||
     version_is_equal(version:rcvRes[1], test_version:"5.5.0")){
    security_warning(port);
  }
}
