###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_int_overflow_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Reader/Acrobat Font Parsing Integer Overflow Vulnerability (Win)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation results in memory corruption via a PDF file containing
  a specially crafted TrueType font.
  Impact Level: Application";
tag_affected = "Adobe Reader version 8.2.3 and 9.3.3
  Adobe Acrobat version 9.3.3 on Windows.";
tag_insight = "The flaw is due to an integer overflow error in 'CoolType.dll' when
  parsing the 'maxCompositePoints' field value in the 'maxp' (Maximum Profile)
  table of a TrueType font.";
tag_solution = "No solution or patch is available as of 6th August, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/";
tag_summary = "This host is installed with Adobe products and are prone to font
  parsing integer overflow vulnerability.";

if(description)
{
  script_id(801419);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-2862");
  script_name("Adobe Reader/Acrobat Font Parsing Integer Overflow Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40766");
  script_xref(name : "URL" , value : "http://www.zdnet.co.uk/news/security-threats/2010/08/04/adobe-confirms-pdf-security-hole-in-reader-40089737/");

  script_description(desc);
  script_summary("Check for the version of Adobe Reader/Acrobat");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_require_keys("Adobe/Acrobat/Win/Ver",
                      "Adobe/Reader/Win/Ver");
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

## Get KB for Adobe Reader
readerVer = get_kb_item("Adobe/Reader/Win/Ver");

if(readerVer != NULL)
{
  ## Check for Adobe Reader versions 8.2.3 and 9.3.3
  if(version_is_equal(version:readerVer, test_version:"8.2.3") ||
     version_is_equal(version:readerVer, test_version:"9.3.3"))
  {
    security_hole(0);
    exit(0);
  }
}

# Get KB for Adobe Acrobat
acrobatVer = get_kb_item("Adobe/Acrobat/Win/Ver");

if(acrobatVer != NULL)
{
  ## Check for Adobe Acrobat version equal to 9.3.3
  if(version_is_equal(version:acrobatVer, test_version:"9.3.3")){
      security_hole(0);
  }
}
