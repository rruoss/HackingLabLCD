###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_mult_vuln_aug12_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mozilla Firefox Multiple Vulnerabilities - August12 (Mac OS X)
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
tag_affected = "Mozilla Firefox version before 15.0 on Mac OS X";
tag_insight = "- An error due to improper restriction of navigation to the about:newtab
    page, which allows remote attackers to execute arbitrary JavaScript code
    with chrome privileges via a crafted web site that triggers creation of a
    new tab and then a new window.
  - An error in the debugger in the developer-tools subsystem fails to
    restrict access to the remote-debugging service when remote debugging
    is disabled and the experimental HTTPMonitor extension has been installed
    and enabled.";
tag_solution = "Upgrade to Mozilla Firefox version 15.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803018);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-3965", "CVE-2012-3973");
  script_bugtraq_id(55249);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-30 15:19:59 +0530 (Thu, 30 Aug 2012)");
  script_name("Mozilla Firefox Multiple Vulnerabilities - August12 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027450");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027451");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-60.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-66.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_require_keys("Mozilla/Firefox/MacOSX/Version");
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
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  # Grep for Firefox version
  if(version_is_less(version:ffVer, test_version:"10.0")||
     version_in_range(version:ffVer, test_version:"11.0", test_version2:"14.0"))
  {
    security_hole(0);
    exit(0);
  }
}