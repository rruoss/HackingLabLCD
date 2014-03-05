###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_sep11_win01.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mozilla Products Multiple Vulnerabilities - Sep 11 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Mozilla Firefox version 3.6.20 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.3 or later
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 3.1.12 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the user running an affected application. Failed exploit
  attempts will result in a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Mozilla Firefox version before 3.6.20
  SeaMonkey version 1.x and 2.0 through 2.2
  Thunderbird version 2.x and 3.0 through 3.1.11";
tag_insight = "The flaws are due to
  - Unspecified errors in the browser engine in mozilla products.
  - Improperly handling of the 'RegExp.input' property, which allows remote
    attackers to bypass the same origin policy and read data from a different
    domain via a crafted web site.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird/seamonkey
  and is prone to multiple unspecified vulnerabilities.";

if(description)
{
  script_id(802151);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-09 17:36:48 +0200 (Fri, 09 Sep 2011)");
  script_cve_id("CVE-2011-2982", "CVE-2011-2983");
  script_bugtraq_id(49216, 49223);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Products Multiple Vulnerabilities - Sep 11 (Windows)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/45666/");
  script_xref(name : "URL" , value : "http://support.avaya.com/css/P8/documents/100146973");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-30.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Thunderbird/SeaMonkey");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl",
                      "gb_seamonkey_detect_win.nasl",
                      "gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Seamonkey/Win/Ver",
                       "Thunderbird/Win/Ver");
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

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"3.6.20")){
     security_hole(0);
     exit(0);
  }
}

# SeaMonkey Check
seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  # Grep for SeaMonkey version
  if((seaVer =~ "^1\.*")||
     version_in_range(version:seaVer, test_version:"2.0", test_version2:"2.2"))
  {
     security_hole(0);
     exit(0);
  }
}

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  # Grep for Thunderbird version
  if((tbVer =~ "^2\.*")||
      version_in_range(version:tbVer, test_version:"3.0", test_version2:"3.1.11")){
    security_hole(0);
  }
}
