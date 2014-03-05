###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_unspecified_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Oracle Java SE Java Runtime Environment Unspecified Vulnerability - (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to gain sensitive information.
  Impact Level: Application";
tag_affected = "Oracle Java SE versions 7 Update 4 and earlier";
tag_insight = "Unspecified errors related to Libraries component.";
tag_solution = "Apply the patch from below link
  http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html";
tag_summary = "This host is installed with Oracle Java SE and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(802950);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1726");
  script_bugtraq_id(53948);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-22 19:06:04 +0530 (Wed, 22 Aug 2012)");
  script_name("Oracle Java SE Java Runtime Environment Unspecified Vulnerability - (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48589");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/80724");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html");
  script_xref(name : "URL" , value : "http://www.metasploit.com/modules/exploit/multi/browser/java_atomicreferencearray");

  script_description(desc);
  script_summary("Check for the version of Sun Java SE JRE");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

  ## Check for Oracle Java SE versions 7 Update 4 and earlier,
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.4")){
    security_hole(0);
  }
}
