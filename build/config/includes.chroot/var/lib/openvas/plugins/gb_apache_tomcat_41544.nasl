###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_41544.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apache Tomcat 'Transfer-Encoding' Information Disclosure and Denial Of Service Vulnerabilities
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
tag_summary = "Apache Tomcat is prone to multiple remote vulnerabilities including
information-disclosure and denial-of-service issues.

Remote attackers can exploit these issues to cause denial-of-service
conditions or gain access to potentially sensitive information;
information obtained may lead to further attacks.

The following versions are affected:

Tomcat 5.5.0 to 5.5.29 Tomcat 6.0.0 to 6.0.27 Tomcat 7.0.0

Tomcat 3.x, 4.x, and 5.0.x may also be affected.";

tag_solution = "The vendor released updates. Please see the references for more
information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100712";
CPE = "cpe:/a:apache:tomcat";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 14 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2010-07-13 12:45:31 +0200 (Tue, 13 Jul 2010)");
 script_bugtraq_id(41544);
 script_tag(name:"cvss_base", value:"6.4");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_cve_id("CVE-2010-2227");

 script_name("Apache Tomcat 'Transfer-Encoding' Information Disclosure and Denial Of Service Vulnerabilities");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/41544");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-6.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-7.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/512272");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Tomcat version is vulnerable.");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_apache_tomcat_detect.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("ApacheTomcat/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

     
include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers)) {

  if(version_in_range(version:vers, test_version:"5.5.0", test_version2:"5.5.29") || 
     version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.28")   ||
     version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.1")) {
      security_hole(port:port);
      exit(0);
  }
}

exit(0);

