###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_jul10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products Multiple Vulnerabilities jul-10 (Windows)
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
tag_solution = "Upgrade to Firefox version 3.5.11 or 3.6.7 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.6 or later
  http://www.seamonkey-project.org/releases/

  Upgrade to Thunderbird version 3.0.6 or 3.1.1 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service
  or execute arbitrary code.
  Impact Level: Application";
tag_affected = "Seamonkey version 2.0.x before 2.0.6
  Firefox version 3.5.x before 3.5.11 and 3.6.x before 3.6.7
  Thunderbird version 3.0.x before 3.0.6 and 3.1.x before 3.1.1";
tag_insight = "The flaws are due to:
  - A memory corruption errors in the browser engine, which allows to corrupt
    the memory under certain circumstances.
  - An integer overflow error exists when array class used to store CSS values,
    which allows to execute arbitrary codes.
  - An integer overflow error in the implementation of the XUL <tree> element's
    'selection' attribute. When the size of a new selection is sufficiently
    large the integer used in calculating the length of the selection, which
    allows attacker to call into deleted memory and run arbitrary code.
  - Error in handling of 'CSS' selector into points A and B of a target page,
    data can be read across domains by injecting bogus CSS selectors into a
    target site and then retrieving the data using JavaScript APIs.
  - Cross-origin data leakage errors occurs from script filename in error
    messages.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird that are
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(801385);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(41824);
  script_cve_id("CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1213",
                "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754",
                "CVE-2010-0654");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Products Multiple Vulnerabilities jul-10 (Windows)");
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

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-34.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-39.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-40.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-42.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-46.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-47.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Seamonkey/Win/Ver", "Thunderbird/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox version 3.5 < 3.5.11, 3.6 < 3.6.7
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.6") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.10"))
     {
       security_hole(0);
       exit(0);
     }
}

## Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  ## Grep for Seamonkey version 2.0 < 2.0.6
  if(version_in_range(version:smVer, test_version:"2.0", test_version2:"2.0.5"))
  {
    security_hole(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version 3.1.0, 3.0 < 3.0.6
  if(version_is_equal(version:tbVer, test_version:"3.1.0") ||
     version_in_range(version:tbVer, test_version:"3.0", test_version2:"3.0.5")){
    security_hole(0);
  }
}
