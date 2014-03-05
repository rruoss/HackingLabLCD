###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln03_jan13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Mozilla Products Multiple Vulnerabilities-03 January13 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_solution = "Upgrade to Mozilla Firefox version 18.0 or ESR version 17.0.1 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.15 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 17.0.2 or ESR version 17.0.1 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation could allow attackers to cause a denial of service
  or execute arbitrary code in the context of the browser.
  Impact Level: System/Application";

tag_affected = "SeaMonkey version before 2.15 on Windows
  Thunderbird version before 17.0.2 on Windows
  Mozilla Firefox version before 18.0 on Windows
  Thunderbird ESR version 17.x before 17.0.1 on Windows
  Mozilla Firefox ESR version 17.x before 17.0.1 on Windows";
tag_insight = "- Use-after-free errors exists within the
    'mozilla::TrackUnionStream::EndTrack' implementation and Mesa when resizing
    a WebGL canvas.
  - Unspecified error in the browser engine can be exploited to corrupt memory.
  - An error within the 'gfxTextRun::ShrinkToLigatureBoundaries()' function.";
tag_summary = "This host is installed with Mozilla Firefox/Thunderbird/Seamonkey and is
  prone to multiple vulnerabilities.";

if(description)
{
  script_id(803202);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0761", "CVE-2013-0763", "CVE-2013-0771", "CVE-2013-0749");
  script_bugtraq_id(57196, 57197, 57198, 57205);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-16 16:20:06 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Products Multiple Vulnerabilities-03 January13 (Windows)");
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

  script_xref(name : "URL" , value : "http://www.osvdb.org/89004");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51752/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027955");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027957");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027958");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Thunderbird/SeaMonkey on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Seamonkey/Win/Ver", "Thunderbird/Win/Ver",
                      "Firefox-ESR/Win/Ver", "Thunderbird-ESR/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

# Firefox Check
ffVer = "";
fesrVer = "";
ffVer = get_kb_item("Firefox/Win/Ver");
fesrVer = get_kb_item("Firefox-ESR/Win/Ver");

if(ffVer || fesrVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"18.0")||
     version_is_equal(version:fesrVer, test_version:"17.0.0"))
  {
    security_hole(0);
    exit(0);
  }
}

# SeaMonkey Check
seaVer = "";
seaVer = get_kb_item("Seamonkey/Win/Ver");

if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.15"))
  {
    security_hole(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = "";
tbesrVer = "";
tbVer = get_kb_item("Thunderbird/Win/Ver");
tbesrVer = get_kb_item("Thunderbird-ESR/Win/Ver");

if(tbVer || tbesrVer)
{
  # Grep for Thunderbird version
  if(version_is_less(version:tbVer, test_version:"17.0.2")||
     version_is_equal(version:tbesrVer, test_version:"17.0.0"))
  {
    security_hole(0);
    exit(0);
  }
}
