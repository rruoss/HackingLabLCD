###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_mozilla_prdts_insecure_lib_load_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products Insecure Library Loading Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow the attackers to execute arbitrary code and
  conduct DLL hijacking attacks.
  Impact Level: Application";
tag_affected = "Thunderbird version 3.1.2
  SeaMonkey version 2.0.6
  Firefox version 3.6.8 and prior on Windows.";
tag_insight = "The flaw is due to the application insecurely loading certain librairies
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a file.";
tag_solution = "No solution or patch is available as of 31st, Aug 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to
  http://www.mozilla.com/en-US/firefox/all.html
  http://www.mozillamessaging.com/en-US/thunderbird/";
tag_summary = "The host is installed with Mozilla Firefox/Seamonkey/Thunderbird and is prone to
  insecure library loading vulnerability.";

if(description)
{
  script_id(902242);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-3131");
  script_name("Mozilla Products Insecure Library Loading Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41095");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14783/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2169");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513324/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Mozilla Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_seamonkey_detect_win.nasl",
                       "gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Thunderbird/Win/Ver",
                      "Seamonkey/Win/Ver");
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

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox version < 3.6.9
  if(version_is_less_equal(version:ffVer, test_version:"3.6.8"))
  {
    security_hole(0);
    exit(0);
  }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Win/Ver");
if(smVer != NULL)
{
  # Grep for Seamonkey version 2.0.6
  if(version_is_equal(version:smVer, test_version:"2.0.6"))
  {
    security_hole(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version 3.1.2
  if(version_is_equal(version:tbVer, test_version:"3.1.2")){
    security_hole(0);
  }
}
