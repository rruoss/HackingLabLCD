###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_win_oct11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mozilla Products Multiple Vulnerabilities - Oct 2011 (Windows)
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
tag_solution = "Upgrade to Mozilla Firefox version 3.6.23 or 7 later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.4 or later
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 7.0 or later
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to bypass intended access
  restrictions via a crafted web site and cause a denial of service
  (memory corruption and application crash) or possibly execute arbitrary
  code via unknown vectors.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version prior to 2.4
  Thunderbird version prior to 7.0
  Mozilla Firefox version prior to 3.6.23 and 4.x through 6";
tag_insight = "The flaws are due to
  - A malicious application or extension could be downloaded and executed if a
    user is convinced into holding down the 'Enter' key via e.g. a malicious
    game.
  - Some unspecified errors can be exploited to corrupt memory.
  - Error while handling HTTP responses that contain multiple Location,
    Content-Length, or Content-Disposition headers, which allows remote
    attackers to conduct HTTP response splitting attacks via crafted header
    values.";
tag_summary = "The host is installed with Mozilla firefox/thunderbird/seamonkey
  and is prone to multiple vulnerabilities.";

if(description)
{
  script_id(802169);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-3000");
  script_bugtraq_id(49811, 49810, 49849);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Products Multiple Vulnerabilities - Oct 2011 (Windows)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/46171/");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-40.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-36.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-39.html");

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
  if(version_is_less(version:ffVer, test_version:"3.6.23") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"6.0")){
     security_hole(0);
     exit(0);
  }
}

# SeaMonkey Check
seaVer = get_kb_item("Seamonkey/Win/Ver");
if(seaVer)
{
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.4"))
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
  if(version_is_less(version:tbVer, test_version:"7.0")){
    security_hole(0);
  }
}
