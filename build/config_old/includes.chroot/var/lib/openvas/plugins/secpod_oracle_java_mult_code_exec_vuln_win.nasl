###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_oracle_java_mult_code_exec_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Oracle Java SE Code Execution Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful attacks will allow attackers to execute arbitrary code in the
  context of the affected application with system privileges.
  Impact Level: Application";
tag_affected = "Oracle Java SE 6 Update 23 and prior.
  Oracle Java SE 5.0 Update 27 and prior.";
tag_insight = "The flaws are due to an error in 'Java Runtime Environment (JRE)',
  which allows remote untrusted Java Web Start applications and untrusted Java
  applets to affect confidentiality and integrity via unknown vectors related
  to JDBC and 2D.";
tag_solution = "Upgrade to Oracle Java SE 6 Update 24 or later
  http://java.com/en/download/index.jsp";
tag_summary = "This host is installed with Sun Java SE and is prone to multiple
  code execution vulnerabilities.";

if(description)
{
  script_id(902353);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2010-4468", "CVE-2010-4471");
  script_bugtraq_id(46393, 46399);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Oracle Java SE Code Execution Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0405");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2011-304611.html");

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
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

# Get KB for JRE Version On Windows
jreVer = get_kb_item("Sun/Java/JRE/Win/Ver");
if(jreVer)
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  # Check version from  1.6 < 1.6.0_23 (6 Update 23), 1.5 < 1.5.0_27(5 Update 27)
  if(version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.23") ||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.27"))
  {
    security_warning(0);
    exit(0);
  }
}

# Get KB for JDK Version On Windows
jdkVer = get_kb_item("Sun/Java/JDK/Win/Ver");
if(jdkVer)
{
  jdkVer = ereg_replace(pattern:"_|-", string:jdkVer, replace: ".");

  # Check version from  1.6 < 1.6.0_23 (6 Update 23), 1.5 < 1.5.0_27(5 Update 27)
  if(version_in_range(version:jdkVer, test_version:"1.6", test_version2:"1.6.0.23") ||
     version_in_range(version:jdkVer, test_version:"1.5", test_version2:"1.5.0.27")){
    security_warning(0);
  }
}
