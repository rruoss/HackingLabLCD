###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_java_mult_unspecified_vuln_win01_jun11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Java SE Multiple Unspecified Vulnerabilities 01 - June11 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code in
  the context of the application.
  Impact Level: Application";
tag_affected = "Oracle Java SE versions 6 Update 25 and prior.";
tag_insight = "Multiple flaws are due to unspecified errors in the following
  components:
  - 2D
  - NIO
  - SAAJ
  - Deployment";
tag_solution = "Upgrade to Oracle Java SE version 6 Update 26 or later.
  For updates refer to http://java.com/en/download/index.jsp";
tag_summary = "This host is installed with Oracle Java SE and is prone to multiple
  unspecified vulnerabilities.";

if(description)
{
  script_id(902525);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_cve_id("CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0872", "CVE-2011-0786",
                "CVE-2011-0788", "CVE-2011-0817", "CVE-2011-0863");
  script_bugtraq_id(48140, 48141, 48146, 48133, 48135, 48134, 48138);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Oracle Java SE Multiple Unspecified Vulnerabilities 01 - June11 (Windows)");
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
  script_summary("Check for the version of Sun Java SE JRE/JDK");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_require_keys("Sun/Java/JRE/Win/Ver", "Sun/Java/JDK/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpujune2011-313339.html");
  exit(0);
}


include("version_func.inc");

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  ## Check for Oracle Java SE versions 6 Update 25 and prior
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.25"))
  {
    security_hole(0);
    exit(0);
  }
}

# Get JDK Version from KB
jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  jdkVer = ereg_replace(pattern:"_|-", string:jdkVer, replace: ".");

  ## Check for Oracle Java SE versions 6 Update 25 and prior
  if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.25")) {
     security_hole(0);
  }
}
