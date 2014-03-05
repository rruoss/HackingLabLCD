###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_mult_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Firefox Multiple Denial Of Service vulnerabilities (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Firefox version 3.6.3 and prior on windows XP SP3 and prior.";
tag_insight = "Multiple flaws are due to
  - A 'NULL' pointer dereference error when handling 'JavaScript' code that
    performs certain string concatenation and substring operations.
  - An out-of-bounds read errors when handling 'JavaScript' code that appends
    long strings to the content of a 'P' element, and performs certain other
    string concatenation and substring operations.
  - An erro when handling 'JavaScript' code that creates multiple arrays
    containing elements with long string values, and then appends long strings
    to the content of a 'P' element.";
tag_solution = "No solution or patch is available as of 21st May, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox and is prone to multiple Denial of
  Service vulnerabilities.";

if(description)
{
  script_id(902186);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1986", "CVE-2010-1987", "CVE-2010-1988");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Firefox Multiple Denial Of Service vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/4206/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511329/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Denial of Service");
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


include("secpod_reg.inc");
include("version_func.inc");

# check windows XP SP3
if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version <= 3.6.3
  if(version_is_less_equal(version:ffVer, test_version:"3.6.3")){
    security_hole(0);
  }
}