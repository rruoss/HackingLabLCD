#############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_unspecified_vuln01_may13_macosx.nasl 29729 2013-05-28 10:51:02Z may$
#
# Adobe Acrobat Multiple Unspecified Vulnerabilities -01 May13 (Mac OS X)
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

CPE = "cpe:/a:adobe:acrobat:";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803617";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 52 $");
  script_cve_id("CVE-2013-3342", "CVE-2013-3341", "CVE-2013-3340", "CVE-2013-3339",
                "CVE-2013-3338", "CVE-2013-3337", "CVE-2013-2737", "CVE-2013-2736",
                "CVE-2013-2735", "CVE-2013-2734", "CVE-2013-2733", "CVE-2013-2732",
                "CVE-2013-2731", "CVE-2013-2730", "CVE-2013-2729", "CVE-2013-2727",
                "CVE-2013-2726", "CVE-2013-2725", "CVE-2013-2724", "CVE-2013-2723",
                "CVE-2013-2722", "CVE-2013-2721", "CVE-2013-2720", "CVE-2013-2719",
                "CVE-2013-2718", "CVE-2013-3346");
  script_bugtraq_id(59930, 59911, 59917, 59906, 59916, 59914, 59926, 59908, 59910,
                    59905, 59925, 59904, 59921, 59923, 59918, 59903, 59920, 59919,
                    59927, 59915, 59913, 59912, 59909, 59907, 59902);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-11-08 19:43:19 +0100 (Fr, 08. Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-05-28 10:51:02 +0530 (Tue, 28 May 2013)");
  script_name("Adobe Acrobat Multiple Unspecified Vulnerabilities -01 May13 (Mac OS X)");

  tag_summary =
"This host is installed with Adobe Acrobat and is prone to multiple unspecified
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"For more information about the vulnerabilities refer the reference links.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary code,
corrupt memory, obtain sensitive information, bypass certain security
restrictions or cause a denial of service condition.

Impact Level: System/Application";

  tag_affected =
"Adobe Acrobat Version 9.x prior to 9.5.5 on Mac OS X
Adobe Acrobat Version 10.x prior to 10.1.7 on Mac OS X
Adobe Acrobat Version 11.x prior to 11.0.03 on Mac OS X";

  tag_solution =
"Update to Adobe Acrobat Version 11.0.03 or 10.1.7 or 9.5.5 or later,
For updates refer to http://www.adobe.com/in/products/acrobat.html";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53420");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-15.html");
  script_summary("Check for the vulnerable version of Adobe Acrobat on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
acrobatVer = "";

## Get version
if(!acrobatVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(acrobatVer && acrobatVer =~ "^9|10|11")
{
  ## Check Adobe Acrobat version is 9.x <= 9.5.4, 10.x <= 10.1.6 and 11.x <= 11.0.02
  if((version_in_range(version:acrobatVer, test_version:"9.0", test_version2: "9.5.4"))||
     (version_in_range(version:acrobatVer, test_version:"10.0", test_version2: "10.1.6"))||
     (version_in_range(version:acrobatVer, test_version:"11.0", test_version2: "11.0.02")))
  {
    security_hole(0);
    exit(0);
  }
}
