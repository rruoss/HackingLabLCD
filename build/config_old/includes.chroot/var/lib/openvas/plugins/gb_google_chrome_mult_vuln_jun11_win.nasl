###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_jun11_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Chrome Multiple Denial of Service Vulnerabilities - June 11(Windows)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, cause denial-of-service conditions, bypass the
  same-origin policy, and disclose potentially sensitive information.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 12.0.742.91 on windows";
tag_insight = "The flaws are due to
  - Use-after-free vulnerability due to integer issues in float handling.
  - Use-after-free vulnerability in accessibility support.
  - Error in 'Cascading Style Sheets (CSS)' implementation, which fails to properly
    restrict access to the visit history, which allows remote attackers to obtain
    sensitive information via unspecified vectors.
  - Not properly handling a large number of form submissions.
  - Bypassing extensions permission.
  - 'Stale pointer' in extension framework.
  - Attempts to read data from an uninitialized pointer.
  - Extension script injection into new tab page.
  - Use-after-free vulnerability in developer tools, image loader
  - Fails to properly implement history deletion.
  - Extension injection into 'chrome://' pages.
  - Same origin bypass in 'v8' and 'DOM'.";
tag_solution = "Upgrade to the Google Chrome 12.0.742.91 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802102);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-13 15:28:04 +0200 (Mon, 13 Jun 2011)");
  script_cve_id("CVE-2011-1808", "CVE-2011-1809", "CVE-2011-1810", "CVE-2011-1811",
                "CVE-2011-1812", "CVE-2011-1813", "CVE-2011-1814", "CVE-2011-1815",
                "CVE-2011-1816", "CVE-2011-1817", "CVE-2011-1818", "CVE-2011-1819",
                "CVE-2011-2332", "CVE-2011-2342");
  script_bugtraq_id(48129);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Google Chrome Multiple Vulnerabilities - June 11(Windows)");
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
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/06/chrome-stable-release.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_require_keys("GoogleChrome/Win/Ver");
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

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 12.0.742.91
if(version_is_less(version:chromeVer, test_version:"12.0.742.91")){
  security_hole(0);
}
