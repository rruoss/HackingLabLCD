###############################################################################
# OpenVAS Vulnerability Test
# $Id: apache_tomcat_multiple_vulnerabilities_jan_10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache Tomcat Multiple Vulnerabilities January 2010
#
# Authors:
# Michael Meyer
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
tag_summary = "Apache Tomcat is prone to a directory-traversal vulnerability and to
an authentication-bypass vulnerability.

Exploiting this issue allows attackers to delete arbitrary files
within the context of the current working directory or gain
unauthorized access to files and directories..

The following versions are affected:

Tomcat 5.5.0 through 5.5.28 
Tomcat 6.0.0 through 6.0.20";


tag_solution = "The vendor has released updates. Please see the references for
details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100474";
CPE = "cpe:/a:apache:tomcat";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-01-28 18:48:47 +0100 (Thu, 28 Jan 2010)");
 script_bugtraq_id(37945,37942,37944);
 script_cve_id("CVE-2009-2901","CVE-2009-2902","CVE-2009-2693");
 script_tag(name:"cvss_base", value:"5.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
 script_tag(name:"risk_factor", value:"High");

 script_name("Apache Tomcat Multiple Vulnerabilities January 2010");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37945");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37944");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37942");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/");
 script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=892815");
 script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=902650");

 script_description(desc);
 script_summary("Determine if Apache Tomcat version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_apache_tomcat_detect.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("ApacheTomcat/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "summary" , value : tag_summary);
 }
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!tomPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!tomcatVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:tomPort))exit(0);

if(version_in_range(version:tomcatVer, test_version:"5.5", test_version2:"5.5.28") ||
   version_in_range(version:tomcatVer, test_version:"6.0", test_version2:"6.0.20")){
   security_hole(tomPort);
   exit(0);
}

exit(0);
     
