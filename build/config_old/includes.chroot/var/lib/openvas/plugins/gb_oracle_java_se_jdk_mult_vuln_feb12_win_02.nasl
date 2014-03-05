###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_jdk_mult_vuln_feb12_win_02.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle Java SE JDK Multiple Vulnerabilities - February 2012 (Windows - 02)
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
tag_impact = "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors.
  Impact Level: System/Application";
tag_affected = "Oracle Java SE JDK 7 Update 2 and earlier, 6 Update 30 and earlier";
tag_insight = "Multiple flaws are caused by unspecified errors in the following
  components:
  - 2D
  - Install
  - Deployment";
tag_solution = "Upgrade to Oracle Java SE JDK versions 7 Update 3, 6 Update 31 or later.
  For updates refer to
  http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html";
tag_summary = "This host is installed with Oracle Java SE JDK and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803335);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0497", "CVE-2012-0500", "CVE-2012-0504");
  script_bugtraq_id(52009, 52015, 52020);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-21 17:17:17 +0530 (Tue, 21 Feb 2012)");
  script_name("Oracle Java SE JDK Multiple Vulnerabilities - February 2012 (Windows - 02)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48009");
  script_xref(name : "URL" , value : "http://www.pre-cert.de/advisories/PRE-SA-2012-01.txt");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html");

  script_description(desc);
  script_summary("Check for the vulnerable version of Oracle Java SE JDK");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JDK/Win/Ver");
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
jdkVer = "";

## Get JDK Version from KB
jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer && jdkVer=~ "^(1.6|1.7)")
{
  jdkVer = ereg_replace(pattern:"_|-", string:jdkVer, replace: ".");

  ## Check for Oracle Java SE JDK 7 Update 2 and earlier, 6 Update 30 and earlier,
  if(version_in_range(version:jdkVer, test_version:"1.7", test_version2:"1.7.0.2")||
     version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.30")){
     security_hole(0);
  }
}
