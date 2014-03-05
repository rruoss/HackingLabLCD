###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln01_jan13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe Acrobat Multiple Vulnerabilities -01 Jan 13 (Windows)
#
# Authors:
# Thanga Prakash s <tprakash@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the affected
  application or cause a denial of service.
  Impact Level: System/Application";

tag_affected = "Adobe Acrobat versions 9.x to 9.5.2, 10.x to 10.1.4 and 11.0.0 on Windows";
tag_insight = "For more details about the vulnerabilities refer the reference section.";
tag_solution = "Upgrade to Adobe Acrobat 9.5.3 or 10.1.5 or 11.0.1 or later,
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Acrobat and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803434);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-1530", "CVE-2013-0601", "CVE-2013-0602", "CVE-2013-0603",
                "CVE-2013-0604", "CVE-2013-0605", "CVE-2013-0606", "CVE-2013-0607",
                "CVE-2013-0608", "CVE-2013-0609", "CVE-2013-0610", "CVE-2013-0611",
                "CVE-2013-0612", "CVE-2013-0613", "CVE-2013-0614", "CVE-2013-0615",
                "CVE-2013-0616", "CVE-2013-0617", "CVE-2013-0618", "CVE-2013-0619",
                "CVE-2013-0620", "CVE-2013-0621", "CVE-2013-0622", "CVE-2013-0623",
                "CVE-2013-0624", "CVE-2013-0626", "CVE-2013-0627");
  script_bugtraq_id(57264, 57272, 57289, 57282, 57283, 57273, 57263, 57290, 57291,
                    57286, 57284, 57292, 57265, 57287, 57293, 57268, 57274, 57269,
                    57294, 57275, 57276, 57270, 57295, 57277, 57296, 57285, 57297);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-12 19:05:12 +0530 (Tue, 12 Mar 2013)");
  script_name("Adobe Acrobat Multiple Vulnerabilities -01 Jan 13 (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/88970");
  script_xref(name : "URL" , value : "http://osvdb.org/88996");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51791");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027952");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-02.html");

  script_description(desc);
  script_summary("Check for the Vulnerable version of Adobe Acrobat on Windows");
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
function version_check(adver)
{
  if(adver =~ "^(9|10|11.0)")
  {
    if(version_in_range(version:adver, test_version:"9.0", test_version2:"9.5.2") ||
       version_in_range(version:adver, test_version:"10.0", test_version2:"10.1.4")||
       version_is_equal(version:adver, test_version:"11.0.0"))
    {
      security_hole(0);
      exit(0);
    }
  }
}

## Get Acrobat version
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(acrobatVer){
  version_check(adver:acrobatVer);
}
