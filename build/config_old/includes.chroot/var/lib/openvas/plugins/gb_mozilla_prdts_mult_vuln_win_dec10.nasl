###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_dec10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products Multiple Vulnerabilities dec-10 (Windows)
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
tag_solution = "Upgrade to Firefox version 3.5.16 or 3.6.13 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.11 or later
  http://www.seamonkey-project.org/releases/

  Upgrade to Thunderbird version 3.0.11 or 3.1.7 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service and
  execute arbitrary code.
  Impact Level: Application";
tag_affected = "Seamonkey version before 2.0.11
  Firefox version before 3.5.16 and 3.6.x before 3.6.13
  Thunderbird version before 3.0.11 and 3.1.x before 3.1.7";
tag_insight = "The flaws are due to:
  - Multiple unspecified vulnerabilities in the browser engine, which allows
    attackers to cause a denial of service.
  - 'Line-breaking' implementation which does not properly handle long strings
    which allow remote attackers to execute arbitrary code via a crafted
    'document.write' call.
  - Not properly validate downloadable fonts before use within an operating
    system's font implementation.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird that are
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(801497);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-3769", "CVE-2010-3768", "CVE-2010-3776");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Products Multiple Vulnerabilities dec-10 (Windows)");
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

  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=660420");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=527276");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-74.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-75.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-78.html");

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
  ## Grep for Firefox version < 3.5.16, 3.6.x < 3.6.13
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.13") ||
     version_is_less(version:ffVer, test_version:"3.5.16"))
     {
       security_hole(0);
       exit(0);
     }
}

## Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  ## Grep for Seamonkey version 2.0.11
  if(version_is_less(version:smVer, test_version:"2.0.11"))
  {
    security_hole(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version < 3.0.11, 3.1.x < 3.1.7
  if(version_in_range(version:tbVer, test_version:"3.1", test_version2:"3.1.7") ||
     version_is_less(version:tbVer, test_version:"3.0.11")){
    security_hole(0);
  }
}
