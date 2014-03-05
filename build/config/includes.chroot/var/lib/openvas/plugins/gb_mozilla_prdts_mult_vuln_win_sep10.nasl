###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_sep10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products Multiple Vulnerabilities sep-10 (Windows)
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
tag_solution = "Upgrade to Firefox version 3.5.12 or 3.6.9 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Seamonkey version 2.0.7 or later
  http://www.seamonkey-project.org/releases/

  Upgrade to Thunderbird version 3.0.7 or 3.1.3 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to cause a denial of service,
  execute arbitrary code, or cause buffer overflow.
  Impact Level: Application";
tag_affected = "Seamonkey version before 2.0.7
  Firefox version 3.5.x before 3.5.12 and 3.6.x before 3.6.9
  Thunderbird version 3.0.x before 3.0.7 and 3.1.x before 3.1.3";
tag_insight = "The flaws are due to:
  - Some pointer held by a 'XUL' tree selection could be freed and then later
    reused, potentially resulting in the execution of attacker-controlled memory.
  - Information leak via 'XMLHttpRequest' statusText.
  - Dangling pointer vulnerability using 'DOM' plugin array.
  - 'Frameset' integer overflow vulnerability.
  - type attribute of an '<object>' tag, which override the charset of a framed
    HTML document.
  - Dangling pointer vulnerability in the implementation of 'navigator.plugins'
    in which the navigator object could retain a pointer to the plugins array
    even after it had been destroyed.
  - Copy-and-paste or drag-and-drop into 'designMode' document allows XSS.
  - Heap buffer overflow in 'nsTextFrameUtils::TransformText'
  - Dangling pointer vulnerability in 'XUL <tree>'s content view.";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird that are
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(801450);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-2760", "CVE-2010-2764", "CVE-2010-2766", "CVE-2010-2765",
                "CVE-2010-2768", "CVE-2010-2767", "CVE-2010-2769", "CVE-2010-3166",
                "CVE-2010-3167", "CVE-2010-3169", "CVE-2010-3168");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Products Multiple Vulnerabilities sep-10 (Windows)");
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

  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-54.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-51.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-56.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-57.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/known-vulnerabilities/firefox36.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/known-vulnerabilities/seamonkey20.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/known-vulnerabilities/thunderbird31.html");

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
  ## Grep for Firefox version 3.5 < 3.5.12, 3.6 < 3.6.9
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.8") ||
     version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.11"))
     {
       security_hole(0);
       exit(0);
     }
}

## Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  ## Grep for Seamonkey version 2.0.7
  if(version_is_less(version:smVer, test_version:"2.0.7"))
  {
    security_hole(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version 3.1 < 3.1.3, 3.0 < 3.0.7
  if(version_in_range(version:tbVer, test_version:"3.1", test_version2:"3.1.2") ||
     version_in_range(version:tbVer, test_version:"3.0", test_version2:"3.0.6")){
    security_hole(0);
  }
}
