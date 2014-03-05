###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_java_se_mult_vuln01_mar13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Oracle Java SE Multiple Vulnerabilities -01 March 13 (Windows)
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary code,
  corrupt memory or cause a denial of service.
  Impact Level: System/Application";

tag_affected = "Oracle Java SE Versions 7 Update 15 and earlier, 6 Update 41 and earlier,
  5 Update 40 and earlier on Windows";
tag_insight = "Multiple flaws due to,
  - Unspecified error in 2D component.
  - Error in color management(CMM) functionality in the 2D component via image
    with crafted raster parameter.";
tag_solution = "Apply patch from below link,
  http://www.oracle.com/technetwork/topics/security/alert-cve-2013-1493-1915081.html";
tag_summary = "This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803327);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1493","CVE-2013-0809");
  script_bugtraq_id(58296,58238);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-07 18:02:25 +0530 (Thu, 07 Mar 2013)");
  script_name("Oracle Java SE Multiple Vulnerabilities -01 March 13 (Windows)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1028237");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/438422.php");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/438437.php");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/alert-cve-2013-1493-1915081.html");

  script_description(desc);
  script_summary("Check for vulnerable version of Oracle Java SE JRE on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_java_prdts_detect_win.nasl");
  script_mandatory_keys("Sun/Java/JRE/Win/Ver");
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

if(jreVer && jreVer=~ "^(1.5|1.6|1.7)")
{
  jreVer = ereg_replace(pattern:"_|-", string:jreVer, replace: ".");

  ##Check for Oracle Java SE Versions
  if(version_in_range(version:jreVer, test_version:"1.7", test_version2:"1.7.0.15")||
     version_in_range(version:jreVer, test_version:"1.6", test_version2:"1.6.0.41")||
     version_in_range(version:jreVer, test_version:"1.5", test_version2:"1.5.0.40"))
  {
    security_hole(0);
    exit(0);
  }
}
