###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_july10_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Acrobat and Reader Multiple Vulnerabilities -July10 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let attackers to crash an affected application or
  execute arbitrary code by tricking a user into opening a specially crafted PDF
  document.
  Impact Level: System/Application";
tag_affected = "Adobe Reader version 8.x before 8.2.3 and 9.x before 9.3.3,
  Adobe Acrobat version 8.x before 8.2.3  and 9.x before 9.3.3 on windows.";
tag_insight = "The flaws are caused by memory corruptions, invalid pointers reference,
  uninitialized memory, array-indexing and use-after-free errors when
  processing malformed data within a PDF document.";
tag_solution = "Upgrade to Adobe Reader/Acrobat version 9.3.3 or 8.2.3
  For updates refer to http://www.adobe.com";
tag_summary = "This host is installed with Adobe Reader/Acrobat and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801365);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_cve_id("CVE-2010-1285", "CVE-2010-1295", "CVE-2010-2168", "CVE-2010-2201",
                "CVE-2010-2202", "CVE-2010-2203", "CVE-2010-2204", "CVE-2010-2205",
                "CVE-2010-2206", "CVE-2010-2207", "CVE-2010-2208", "CVE-2010-2209",
                "CVE-2010-2210", "CVE-2010-2211", "CVE-2010-2212");
  script_bugtraq_id(41230, 41232, 41236, 41234, 41235, 41231, 41231, 41241, 41239,
                    41244, 41240, 41242, 41243, 41245);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Acrobat and Reader Multiple Vulnerabilities -July10 (Windows)");
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
  script_xref(name : "URL" , value : "http://isc.incidents.org/diary.html?storyid=9100");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1636");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb10-15.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Acrobat/Win/Ver", "Adobe/Reader/Win/Ver");
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

readerVer = get_kb_item("Adobe/Reader/Win/Ver");
if(readerVer)
{
  # Check for Adobe Reader version 9.x to 9.3.2, and 8.0 to 8.2.2
  if(version_in_range(version:readerVer, test_version:"8.0", test_version2:"8.2.2") ||
     version_in_range(version:readerVer, test_version:"9.0", test_version2:"9.3.2"))
  {
    security_hole(0);
    exit(0);
  }
}

acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");
if(!acrobatVer){
  exit(0);
}

# Check for Adobe Acrobat version 9.x to 9.3.2, and 8.0 < 8.2.3
if(version_in_range(version:acrobatVer, test_version:"8.0", test_version2:"8.2.2") ||
   version_in_range(version:acrobatVer, test_version:"9.0", test_version2:"9.3.3")){
  security_hole(0);
}
