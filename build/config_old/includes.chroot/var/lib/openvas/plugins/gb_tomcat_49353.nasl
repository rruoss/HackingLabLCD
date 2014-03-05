###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tomcat_49353.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apache Tomcat AJP Protocol Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
tag_summary = "Apache Tomcat is prone to a security-bypass vulnerability.

Successful exploits will allow attackers to bypass certain security
restrictions.";

tag_solution = "Updates are available. Please see the references for more information.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103242";
CPE = "cpe:/a:apache:tomcat";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 13 $");
 script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
 script_tag(name:"creation_date", value:"2011-09-08 12:04:18 +0200 (Thu, 08 Sep 2011)");
 script_bugtraq_id(49353);
 script_cve_id("CVE-2011-3190");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");


 script_name("Apache Tomcat AJP Protocol Security Bypass Vulnerability");

desc = "
 Summary:
 " + tag_summary + "
 Solution:
 " + tag_solution;
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49353");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-6.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/security-7.html");
 script_xref(name : "URL" , value : "http://tomcat.apache.org/");

 script_tag(name:"risk_factor", value:"High");
 script_description(desc);
 script_summary("Determine if installed Tomcat version is vulnerable");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_apache_tomcat_detect.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("ApacheTomcat/installed");
 if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
   script_tag(name : "solution" , value : tag_solution);
   script_tag(name : "summary" , value : tag_summary);
 }
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
include("global_settings.inc");

if(report_paranoia < 2) exit(0); # this nvt is pront to FP

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers)) {

  if(version_in_range(version:vers, test_version:"7.0",  test_version2:"7.0.20") ||
     version_in_range(version:vers, test_version:"6.0",  test_version2:"6.0.33") ||
     version_in_range(version:vers, test_version:"5",    test_version2:"5.5.33")) {
    
      security_hole(port:port);
      exit(0);

  }

}
