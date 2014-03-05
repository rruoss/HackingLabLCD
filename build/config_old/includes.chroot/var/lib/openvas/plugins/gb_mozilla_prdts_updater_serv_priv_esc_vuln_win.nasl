###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_updater_serv_priv_esc_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mozilla Products Updater Service Privilege Escalation Vulnerabilities (Win)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Mozilla Firefox version 13.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.10 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 13.0 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful attempt could allow local attackers to bypass security restrictions
  and gain the privileges.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version 2.9,
  Thunderbird version 12.0 and
  Mozilla Firefox version 12.0 on Windows";
tag_insight = "- Mozilla updater allows to load a local DLL file in a privileged context.
  - The 'Updater.exe' in the Windows Updater Service allows to load an
    arbitrary local wsock32.dll file, which can then be run with the same
    system privileges used by the service.";
tag_summary = "This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802867);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1942", "CVE-2012-1943");
  script_bugtraq_id(53803, 53807);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-19 12:31:59 +0530 (Tue, 19 Jun 2012)");
  script_name("Mozilla Products Updater Service Privilege Escalation Vulnerabilities (Win)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/49368");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49366");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-35.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Thunderbird/SeaMonkey on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

# Firefox Check
ffVer = "";
ffVer = get_kb_item("Firefox/Win/Ver");

if(ffVer)
{
  # Grep for Firefox version equal to 12.0
  if(version_is_equal(version:ffVer, test_version:"12.0"))
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
  # Grep for SeaMonkey version equal to 2.9
  if(version_is_equal(version:seaVer, test_version:"2.9"))
  {
    security_hole(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = "";
tbVer = get_kb_item("Thunderbird/Win/Ver");

if(tbVer)
{
  # Grep for Thunderbird version equal to 12.0
  if(version_is_equal(version:tbVer, test_version:"12.0"))
  {
    security_hole(0);
    exit(0);
  }
}
