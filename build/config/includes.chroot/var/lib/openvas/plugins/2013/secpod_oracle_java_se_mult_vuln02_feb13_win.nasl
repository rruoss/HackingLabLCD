###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_java_se_mult_vuln02_feb13_win.nasl 28074 2013-02-22 13:41:39Z feb$
#
# Oracle Java SE Multiple Vulnerabilities -02 Feb 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows remote attackers to affect confidentiality,
  integrity and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system.
  Impact Level: System/Application";

tag_affected = "Oracle Java SE Version 7 Update 13 and earlier, 6 Update 39 and earlier,
  5 Update 39 and earlier.";
tag_insight = "Multiple flaws due to unspecified errors in the following components:
  - Deployment
  - Libraries
  - Java Management Extensions (JMX)";
tag_solution = "Apply patch from below link,
  http://www.oracle.com/technetwork/topics/security/javacpufeb2013update-1905892.html";
tag_summary = "This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(903203);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1484","CVE-2013-1485","CVE-2013-1486","CVE-2013-1487");
  script_bugtraq_id(58027,58028,58029,58031);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-22 13:41:39 +0530 (Fri, 22 Feb 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -02 Feb 13 (Windows)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1028155");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2013update-1905892.html");

  script_description(desc);
  script_summary("Check for vulnerable version of Oracle Java SE JRE on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_require_keys("Sun/Java/JRE/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

include("version_func.inc");

## Variable Initialization
jreVer = "";

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  ##Check for Oracle Java SE Versions
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.13")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.39")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.39"))
  {
    security_hole(0);
    exit(0);
  }
}
