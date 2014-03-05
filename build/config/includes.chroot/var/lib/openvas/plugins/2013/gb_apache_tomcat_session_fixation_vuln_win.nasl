###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_session_fixation_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Apache Tomcat Session Fixation Vulnerability (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Apply patch or upgrade Apache Tomcat to 7.0.33 or 6.0.37 or later,
  For updates refer to http://tomcat.apache.org

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation will allow attackers to conduct session fixation
  attacks to hijack the target user's session.
  Impact Level: Application";

tag_affected = "Apache Tomcat version 6.0.21 before 6.0.37 and 7.x before 7.0.33";
tag_insight = "Flaw due to improper validation of session cookies in the FormAuthenticator
  module in 'java/org/apache/catalina/authenticator/FormAuthenticator.java'.";
tag_summary = "The host is running Apache Tomcat Server and is prone to session
  fixation vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803636";
CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2067");
  script_bugtraq_id(59799);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-06-06 12:57:30 +0530 (Thu, 06 Jun 2013)");
  script_name("Apache Tomcat Session Fixation Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/84154");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-6.html");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-7.html");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1417891");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1408044");
  script_summary("Check for the vulnerable version of Apache Tomcat on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheTomcat/installed");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

## variable initialization
tomport = 0;
tomvers = "";

## Exit if its not windows
if(host_runs("Windows") != "yes")exit(0);

## get the port
if(!tomport = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## check the port state
if(!get_port_state(tomport))exit(0);

## get the version
if(!tomvers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:tomport))exit(0);

## check the version for 6.0.21 < 6.0.37 and 7.0 < 7.0.33
if(!isnull(tomvers) && tomvers =~ "^(6|7)")
{
  if(version_in_range(version:tomvers, test_version:"6.0.21", test_version2:"6.0.36")||
    version_in_range(version:tomvers, test_version:"7.0", test_version2:"7.0.32"))
  {
    security_hole(port:tomport);
    exit(0);
  }
}