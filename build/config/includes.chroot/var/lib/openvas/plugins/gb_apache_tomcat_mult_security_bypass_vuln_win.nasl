###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_mult_security_bypass_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apache Tomcat Multiple Security Bypass Vulnerabilities (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allows remote attackers to bypass intended
  access restrictions or gain sensitive information.
  Impact Level: Application.";
tag_affected = "Apache Tomcat 5.5.x to 5.5.33, 6.x to 6.0.32 and 7.x to 7.0.11 on Windows.";
tag_insight = "The flaws are due to errors in the HTTP Digest Access Authentication
  implementation,
  - which fails to check 'qop' and 'realm' values and allows to bypass
    access restrictions.
  - Catalina used as the hard-coded server secret in the
    DigestAuthenticator.java bypasses cryptographic protection mechanisms.
  - which fails to have the expected countermeasures against replay attacks.";
tag_solution = "Upgrade Apache Tomcat to 5.5.34, 6.0.33, 7.0.12 or later,
  For updates refer to http://tomcat.apache.org/";
tag_summary = "The host is running Apache Tomcat Server and is prone to multiple
  security bypass vulnerabilities.";

if(description)
{
  script_id(802415);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-1184" ,"CVE-2011-5062", "CVE-2011-5063", "CVE-2011-5064");
  script_bugtraq_id(49762);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-01-16 15:35:35 +0530 (Mon, 16 Jan 2012)");
  script_name("Apache Tomcat Multiple Security Bypass Vulnerabilities (Win)");
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
  script_summary("Check for the version of Apache Tomcat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect_win.nasl");
  script_require_keys("ApacheTomcat/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-5.html");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-6.html");
  script_xref(name : "URL" , value : "http://tomcat.apache.org/security-7.html");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1158180");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1159309");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc?view=revision&amp;revision=1087655");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
tomcatVer = get_kb_item("ApacheTomcat/Win/Ver");
if(!tomcatVer){
  exit(0);
}

# Check Tomcat version < 5.5.33, or < 6.0.34 or 7.0.12
if(version_in_range(version:tomcatVer, test_version:"5.5", test_version2:"5.5.33")||
   version_in_range(version:tomcatVer, test_version:"6.0", test_version2:"6.0.32")||
   version_in_range(version:tomcatVer, test_version:"7.0", test_version2:"7.0.11")){
  security_warning(tomPort);
}
