###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_code_exec_vuln_jun12_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mozilla Products 'nsHTMLSelectElement' Remote Code Execution Vulnerability (Mac)
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
tag_solution = "Upgrade to Mozilla Firefox version 9.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.6 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 9.0 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the browser.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version before 2.6,
  Thunderbird version 5.0 through 8.0,
  Mozilla Firefox version 4.x through 8.0 on Mac OS X.";
tag_insight = "A use-after-free error exists in 'nsHTMLSelectElement' when the parent node
  of the element is no longer active.";
tag_summary = "This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to remote code execution vulnerability.";

if(description)
{
  script_id(802875);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3671");
  script_bugtraq_id(54080);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-20 13:43:30 +0530 (Wed, 20 Jun 2012)");
  script_name("Mozilla Products 'nsHTMLSelectElement' Remote Code Execution Vulnerability (Mac)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/47302");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027183");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-41.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Thunderbird/SeaMonkey on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_require_keys("Mozilla/Firefox/MacOSX/Version",
                      "SeaMonkey/MacOSX/Version", "ThunderBird/MacOSX/Version");
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
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  # Grep for Firefox version 4.x through 8.0
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"8.0"))
  {
    security_hole(0);
    exit(0);
  }
}

# SeaMonkey Check
seaVer = "";
seaVer = get_kb_item("SeaMonkey/MacOSX/Version");

if(seaVer)
{
  # Grep for SeaMonkey version < 2.6
  if(version_is_less(version:seaVer, test_version:"2.6"))
  {
    security_hole(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = "";
tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(tbVer)
{
  # Grep for Thunderbird version 5.0 through 8.0
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"8.0"))
  {
    security_hole(0);
    exit(0);
  }
}