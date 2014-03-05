###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln_jul12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mozilla Firefox Multiple Vulnerabilities - July12 (Windows)
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
tag_impact = "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser.
  Impact Level: System/Application";
tag_affected = "Mozilla Firefox version 4.x through 13.0
  Mozilla Firefox ESR version 10.x before 10.0.6 on Windows";
tag_insight = "- The improper implementation of drag-and-drop feature, fails to display
    the URL properly in addressbar.
  - An error when handling 'feed:' URLs can be exploited to bypass the output
    filters and execute arbitrary JavaScript code.
  - The context-menu restrictions for data: URLs are not the same as for
    javascript: URLs, which allows to conduct XSS attacks.";
tag_solution = "Upgrade to Mozilla Firefox version 14.0 or ESR version 10.0.6 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla firefox and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802891);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1950", "CVE-2012-1965", "CVE-2012-1966");
  script_bugtraq_id(54580, 54578, 54586);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-23 18:31:44 +0530 (Mon, 23 Jul 2012)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - July12 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49965");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027256");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027257");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-43.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-46.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-55.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

# Firefox Check
ffVer = "";
ffVer = get_kb_item("Firefox/Win/Ver");

if(ffVer)
{
  # Grep for Firefox version
  if(version_in_range(version:ffVer, test_version:"4.0", test_version2:"10.0.5")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"13.0"))
  {
    security_hole(0);
    exit(0);
  }
}
