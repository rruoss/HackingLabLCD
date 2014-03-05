###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_acrobat_mult_vuln_aug12_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Acrobat Multiple Vulnerabilities - Mac OS X
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
  the context of the affected application or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Adobe Acrobat versions 9.x through 9.5.1 and 10.x through 10.1.3 on Mac OS X";
tag_insight = "The flaws are due to unspecified errors which can be exploited to
  corrupt memory.";
tag_solution = "Upgrade to Adobe Acrobat version 9.5.2 or 10.1.4 or later
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Acrobat and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803478);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4149", "CVE-2012-4148", "CVE-2012-4147", "CVE-2012-2051",
                "CVE-2012-2050", "CVE-2012-4160", "CVE-2012-2049", "CVE-2012-4159",
                "CVE-2012-4158", "CVE-2012-4157", "CVE-2012-4156", "CVE-2012-4155",
                "CVE-2012-4154", "CVE-2012-4153", "CVE-2012-1525", "CVE-2012-4152",
                "CVE-2012-4151", "CVE-2012-4150", "CVE-2012-4161", "CVE-2012-4162");
  script_bugtraq_id(55008, 55007, 55006, 55005, 55026, 55021, 55024, 55020, 55019,
                    55018, 55017, 55016, 55015, 55012, 55027, 55013, 55010, 55011,
                    55022, 55023);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-20 11:01:35 +0530 (Mon, 20 Aug 2012)");
  script_name("Adobe Acrobat Multiple Vulnerabilities - Mac OS X");
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
  script_xref(name : "URL" , value : "http://osvdb.org/84614");
  script_xref(name : "URL" , value : "http://osvdb.org/84615");
  script_xref(name : "URL" , value : "http://osvdb.org/84616");
  script_xref(name : "URL" , value : "http://osvdb.org/84617");
  script_xref(name : "URL" , value : "http://osvdb.org/84618");
  script_xref(name : "URL" , value : "http://osvdb.org/84619");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50281");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-16.html");
  script_summary("Check for the version of Adobe Acrobat on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Acrobat/MacOSX/Version");
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
  if(version_in_range(version:ver, test_version:"9.0", test_version2:"9.5.1") ||
     version_in_range(version:ver, test_version:"10.0", test_version2:"10.1.3"))
  {
    security_hole(0);
    exit(0);
  }
}

## Get Acrobat version
acrobatVer = get_kb_item("Adobe/Acrobat/MacOSX/Version");
if(acrobatVer){
  version_check(ver:acrobatVer);
}
