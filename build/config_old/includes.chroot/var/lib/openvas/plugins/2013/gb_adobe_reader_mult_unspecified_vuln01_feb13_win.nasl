###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_reader_mult_unspecified_vuln01_feb13_win.nasl 27950 2013-02-19 18:24:49Z feb$
#
# Adobe Reader Multiple Unspecified Vulnerabilities -01 Feb13 (Windows)
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code or
  cause a denial of service via a crafted PDF document.

  Impact level: System/Application";


tag_affected = "Adobe Reader Version 9.x prior to 9.5.4 on Windows
  Adobe Reader X Version 10.x prior to 10.1.6 on Windows
  Adobe Reader XI Version 11.x prior to 11.0.02 on Windows";
tag_insight = "The flaws are due to unspecified errors.";
tag_solution = "No solution or patch is available as of 19th February, 2013. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader and is prone to multiple
  unspecified vulnerabilities.";

if(description)
{
  script_id(803415);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57931, 57947);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-19 18:24:49 +0530 (Tue, 19 Feb 2013)");
  script_cve_id("CVE-2013-0640", "CVE-2013-0641");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities -01 Feb13 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52196");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/advisories/apsa13-02.html");
  script_xref(name : "URL" , value : "http://blogs.adobe.com/psirt/2013/02/adobe-reader-and-acrobat-vulnerability-report.html");

  script_description(desc);
  script_summary("Check for the vulnerable version of Adobe Reader on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Reader/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

## Variable Initialization
readerVer = "";

readerVer = get_kb_item("Adobe/Reader/Win/Ver");

if(readerVer && readerVer =~ "^9|10|11")
{
  # Check Adobe Reader version is 9.x <= 9.5.3, 10.x <= 10.1.5 and 11.x <= 11.0.01
  if((version_in_range(version:readerVer, test_version:"9.0", test_version2: "9.5.3"))||
     (version_in_range(version:readerVer, test_version:"10.0", test_version2: "10.1.5"))||
     (version_in_range(version:readerVer, test_version:"11.0", test_version2: "11.0.01")))
  {
    security_hole(0);
    exit(0);
  }
}
