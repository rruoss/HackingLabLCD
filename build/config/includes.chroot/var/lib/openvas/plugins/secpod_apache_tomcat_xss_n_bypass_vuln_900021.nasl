##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_tomcat_xss_n_bypass_vuln_900021.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Apache Tomcat Cross-Site Scripting and Security Bypass Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could cause execution of arbitrary
        HTML code, script code, and information disclosure.
 Impact Level : Application.";

tag_solution = "Upgrade to higher version of 4.x, 5.x, or 6.x series.
 http://tomcat.apache.org/";

tag_affected = "Apache Tomcat 4.1.0 - 4.1.37, 5.5.0 - 5.5.26, and 6.0.0 - 6.0.16
	on All Platforms.";

tag_insight = "The flaws are due to,
        - input validation error in the method HttpServletResponse.sendError() which
          fails to properly sanitise before being returned to the user in the
          HTTP Reason-Phrase.
        - the application fails to normalize the target path before removing
          the query string when using a RequestDispatcher.";


tag_summary = "This host is running Apache Tomcat web server, which is prone to
 cross site scripting and security bypass vulnerabilities.";

if(description)
{
 script_id(900021);
 script_version("$Revision: 16 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2008-08-07 17:25:16 +0200 (Thu, 07 Aug 2008)");
 script_bugtraq_id(30494, 30496);
 script_cve_id("CVE-2008-1232", "CVE-2008-2370");
 script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_name("Apache Tomcat Cross-Site Scripting and Security Bypass Vulnerabilities");
 script_summary("Check for vulnerable version of Apache Tomcat");
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
 script_description(desc);
 script_dependencies("http_version.nasl");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31379/");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31381/");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
   script_tag(name : "insight" , value : tag_insight);
   script_tag(name : "affected" , value : tag_affected);
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "impact" , value : tag_impact);
 }
 exit(0);
}


 include("http_func.inc");
 include("http_keepalive.inc");

 port = 8080;
 if(!port){
	exit(0);
 }

 sndReq = http_get(item:string("/index.jsp"), port:port);
 rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:1);
 if(rcvRes == NULL){
        exit(0);
 }

 if(egrep(pattern:"<title>Apache Tomcat", string:rcvRes))
 {
	# Grep for Apache Tomcat 4.1.0 - 4.1.37, 5.5.0 - 5.5.26, 6.0.0 - 6.0.16
        if(egrep(pattern:"Apache Tomcat/(4\.1(\.[0-2]?[0-9]|\.3[0-7])?|5\.5" +
			 "(\.[01]?[0-9]|\.2[0-6])?|6\.0(\.[0-9]|\.1[0-6])?)" +
			 "[^.0-9]", string:rcvRes)){
                       security_warning(port);
        }
 }
