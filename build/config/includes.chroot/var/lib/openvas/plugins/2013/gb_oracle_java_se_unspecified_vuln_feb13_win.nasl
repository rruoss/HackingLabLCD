###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_unspecified_vuln_feb13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Oracle Java SE Unspecified Vulnerability - Feb 13 (Windows)
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code
  via unknown vectors.
  Impact Level: System/Application";

tag_affected = "Oracle Java version 7 Update 11 on Windows";
tag_insight = "Unspecified vulnerability allows remote attackers to bypass Java security
  sandbox via unknown vectors.";
tag_solution = "No solution or patch is available as of 06th February, 2013.
  Information regarding this issue will be updated once the solution details
  are available. For updates refer to
  http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html";
tag_summary = "This host is installed with Oracle Java SE and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(803306);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1490");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-06 10:54:26 +0530 (Wed, 06 Feb 2013)");
  script_name("Oracle Java SE Unspecified Vulnerability - Feb 13 (Windows)");
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
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2013/Jan/142");
  script_xref(name : "URL" , value : "http://www.security-database.com/detail.php?alert=CVE-2013-1490");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2013-1841061.html");

  script_description(desc);
  script_summary("Check for the vulnerable version of Oracle Java SE JRE on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
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


## Variable Initialization
jreVer = "";

## Get JRE Version from KB
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");

if(jreVer)
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  ## Check for Oracle Java SE version 1.7.0_11
  if(jreVer == "1.7.0.11")
  {
    security_warning(0);
    exit(0);
  }
}
