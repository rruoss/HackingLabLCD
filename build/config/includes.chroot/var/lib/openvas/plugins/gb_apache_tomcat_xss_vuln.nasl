###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apache Tomcat cal2.jsp Cross Site Scripting Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow remote attackers to inject arbitrary HTML
  codes in the context of the affected web application.
  Impact Level: Application";
tag_affected = "Apache Tomcat version 4.1.0 to 4.1.39, 5.5.0 to 5.5.27 and 6.0.0 to 6.0.18";
tag_insight = "The issue is due to input validation error in time parameter in
  'jsp/cal/cal2.jsp' file in calendar application.";
tag_solution = "Update your cal2.jsp through SVN.
  Revision numbers are 750924 or 750928.
  http://tomcat.apache.org/security-6.html
  http://tomcat.apache.org/security-5.html
  http://tomcat.apache.org/security-4.html";
tag_summary = "This host is running Apache Tomcat and is prone to Cross Site Scripting
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800372";
CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-0781");
  script_name("Apache Tomcat cal2.jsp Cross Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.packetstormsecurity.org/0903-exploits/CVE-2009-0781.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/501538/100/0/threaded");

  script_description(desc);
  script_summary("Check version of Apache Tomcat or XSS Check");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_tomcat_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("ApacheTomcat/installed");
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
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
tomcatVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port);

if(!safe_checks())
{
  # XSS attack string test in 'time' parameter inside cal2.jsp page
  sndReq = string("GET /jsp-examples/cal/cal2.jsp?time=%74%65%73%74%3C%73%63%72%69"+
                  "%70%74%3E%61%6C%65%72%74%28%22%61%74%74%61%63%6B%22%29%3B%3C" +
                  "%2F%73%63%72%69%70%74%3E \r\n\r\n");
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
  if(rcvRes == NULL){
    exit(0);
  }

  if("test" >< rcvRes && "attack" >< rcvRes)
  {
    security_warning(port);
    exit(0);
  }
} else {

  if(version_in_range(version:tomcatVer, test_version:"4.1.0", test_version2:"4.1.39") ||
     version_in_range(version:tomcatVer, test_version:"5.5.0", test_version2:"5.5.27") ||
     version_in_range(version:tomcatVer, test_version:"6.0.0", test_version2:"6.0.18")){
    security_warning(port);
  }
}
