###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_deployment_unspec_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Java SE Java Runtime Environment Unspecified Vulnerability - October 2011 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  integrity, and availability via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Oracle Java SE versions 6 Update 27 and earlier.";
tag_insight = "The flaw is due to unspecified error in the 'Deployment' sub-component.";
tag_solution = "Upgrade to Oracle Java SE versions 6 Update 29 or later.
  For updates refer to
  http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html";
tag_summary = "This host is installed with Oracle Java SE and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(802278);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-3516");
  script_bugtraq_id(50229);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-11-15 14:34:22 +0530 (Tue, 15 Nov 2011)");
  script_name("Oracle Java SE Java Runtime Environment Unspecified Vulnerability - October 2011 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46512");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html");

  script_description(desc);
  script_summary("Check for the version of Sun Java SE JRE/JDK");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
  exit(0);
}


include("version_func.inc");

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  ## Check for Oracle Java SE versions 6 Update 27 and earlier
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.27"))
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

  ## Check for Oracle Java SE versions 6 Update 27 and earlier
  if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.27")) {
    security_hole(0);
  }
}
