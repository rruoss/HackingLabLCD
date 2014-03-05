###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_unspecified_vuln_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe Acrobat Multiple Unspecified Vulnerabilities - Windows
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the affected application.
  Impact Level: System/Application";

tag_affected = "Adobe Acrobat versions 9.x to 9.5.2 and 10.x to 10.1.4 on Windows";
tag_insight = "The flaws are due to an unspecified errors.";
tag_solution = "Upgrade to Adobe Acrobat 9.5.3, 10.1.5 or later,
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Acrobat and is prone to
  multiple unspecified vulnerabilities.";

if(description)
{
  script_id(803803);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-4363");
  script_bugtraq_id(55055);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2012-08-24 16:05:37 +0530 (Fri, 24 Aug 2012)");
  script_name("Adobe Acrobat Multiple Unspecified Vulnerabilities - Windows");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50290");
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
  if(version_is_less(version:ver, test_version:"9.5.3") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.4"))
  {
    security_hole(0);
    exit(0);
  }
}

## Get Acrobat version
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer){
  version_check(ver:acrobatVer);
}
