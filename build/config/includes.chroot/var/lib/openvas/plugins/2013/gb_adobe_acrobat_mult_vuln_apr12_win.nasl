###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln_apr12_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe Acrobat Multiple Vulnerabilities April-2012 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to bypass certain security
  restrictions, execute arbitrary code via unspecified vectors or cause a
  denial of service.
  Impact Level: System/Application";

tag_affected = "Adobe Acrobat version 9.x to 9.5 and prior and 10.x to 10.1.2 on Windows";
tag_insight = "The flaws are due to
  - An unspecified error when handling JavaScript/JavaScript API can be
    exploited to corrupt memory.
  - An integer overflow error when handling True Type Font (TTF) can be
    exploited to corrupt memory.
  - The application loads executables (msiexec.exe) in an insecure manner.";
tag_solution = "Upgrade to Adobe Acrobat version 9.5.1 or 10.1.3 on later,
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Acrobat and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803829);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-0776", "CVE-2012-0774", "CVE-2012-0775");
  script_bugtraq_id(52952, 52951, 52949);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-11 15:18:22 +0530 (Thu, 11 Jul 2013)");
  script_name("Adobe Acrobat Multiple Vulnerabilities April-2012 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48733");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026908");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-08.html");
  script_summary("Check for the version of Adobe Acrobat on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Acrobat/Win/Ver");
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
acrobatVer = "";

## Function to check the versions of abode acrobat
function version_check(ver)
{
  if(version_in_range(version:ver, test_version:"9.0", test_version2:"9.5") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.2"))
  {
    security_hole(0);
    exit(0);
  }
}

## Get Acrobat version
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer && acrobatVer =~ "^(9|10)"){
  version_check(ver:acrobatVer);
}
