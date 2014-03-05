###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_unspecified_vuln_oct10_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Firefox Unspecified Vulnerability Oct-10 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code via
  unknown vectors.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version 3.5.x through 3.5.14
  Mozilla Firefox version 3.6.x through 3.6.11";
tag_insight = "The flaw is due to unspecified vulnerability, when JavaScript is
  enabled.";
tag_solution = "No solution or patch is available as of 29th October, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mozilla.com/en-US/firefox/upgrade.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(801475);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-02 18:01:36 +0100 (Tue, 02 Nov 2010)");
  script_cve_id("CVE-2010-3765");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Firefox Unspecified Vulnerability Oct-10 (Windows)");
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
  script_xref(name : "URL" , value : "http://isc.sans.edu/diary.html?storyid=9817");
  script_xref(name : "URL" , value : "http://www.norman.com/about_norman/press_center/news_archive/2010/129223/");
  script_xref(name : "URL" , value : "http://blog.mozilla.com/security/2010/10/26/critical-vulnerability-in-firefox-3-5-and-firefox-3-6/");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
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

## Get Firefox version from KB
fpVer = get_kb_item("Firefox/Win/Ver");
if(!fpVer){
  exit(0);
}

## Check for Mozilla Firefox Version  3.5 to 3.5.14 and 3.6 to 3.6.11
if(version_in_range(version:fpVer, test_version:"3.5.0", test_version2:"3.5.14")||
   version_in_range(version:fpVer, test_version:"3.6.0", test_version2:"3.6.11")){
  security_hole(0);
}
