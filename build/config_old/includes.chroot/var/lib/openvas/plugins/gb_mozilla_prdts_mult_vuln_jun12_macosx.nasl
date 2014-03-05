###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln_jun12_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mozilla Products Multiple Vulnerabilities - June12 (Mac OS X)
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
tag_solution = "Upgrade to Mozilla Firefox version 13.0 or ESR version 10.0.5 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to SeaMonkey version to 2.10 or later,
  http://www.mozilla.org/projects/seamonkey/

  Upgrade to Thunderbird version to 13.0 or ESR 10.0.5 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "SeaMonkey version before 2.10,
  Thunderbird version 5.0 through 12.0,
  Mozilla Firefox version 4.x through 12.0,
  Thunderbird ESR version 10.x before 10.0.5 and
  Mozilla Firefox ESR version 10.x before 10.0.5 on Mac OS X";
tag_insight = "- Multiple unspecified errors in browser engine can be exploited to corrupt
    memory.
  - Multiple use-after-free errors exists in 'nsFrameList::FirstChild' when
    handling column layouts with absolute positioning within a container that
    changes the size.
  - The improper implementation of Content Security Policy inline-script
    blocking feature, fails to block inline event handlers such as onclick.
  - An error when loading HTML pages from Windows shares, which can be
    exploited to disclose files from local resources via an iframe tag.
  - An error exists within 'utf16_to_isolatin1' function when converting
    from unicode to native character sets.
  - An error in 'nsHTMLReflowState::CalculateHypotheticalBox' when a window is
    resized on a page with nested columns using absolute and relative
    positioning.
  - The glBufferData function in the WebGL implementation, fails to mitigate
    an unspecified flaw in an NVIDIA driver.";
tag_summary = "This host is installed with Mozilla firefox/thunderbird/seamonkey and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802866);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1944", "CVE-2012-1945",
                "CVE-2012-1946", "CVE-2012-1947", "CVE-2012-3105", "CVE-2012-1941",
                "CVE-2012-0441", "CVE-2012-1938");
  script_bugtraq_id(53223, 53220, 53221, 53225, 53219, 53218, 53228,
                    53229, 53227, 53224, 53798, 53796);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-19 11:31:59 +0530 (Tue, 19 Jun 2012)");
  script_name("Mozilla Products Multiple Vulnerabilities - June12 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027120");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-34.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-36.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-37.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-38.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-40.html");

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
  # Grep for Firefox version
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"10.0.4")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"12.0"))
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
  # Grep for SeaMonkey version
  if(version_is_less(version:seaVer, test_version:"2.10"))
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
  # Grep for Thunderbird version
  if(version_in_range(version:tbVer, test_version:"5.0", test_version2:"10.0.4")||
     version_in_range(version:tbVer, test_version:"11.0", test_version2:"12.0"))
  {
    security_hole(0);
    exit(0);
  }
}
