###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_cache_history_info_disc_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Chrome Cache History Information Disclosure Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information about visited web page.
  Impact Level: Application";
tag_affected = "Google Chrome version 15.0.874.121 and prior on Windows";
tag_insight = "Multiple flaws are due to improper capturing of data about the times
  of Same Origin Policy violations during IFRAME and image loading attempts,
  allows attacker to enumerate visited sites via crafted JavaScript code.";
tag_solution = "No solution or patch is available as of 09th December, 2011. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to information
  disclosure vulnerabilities.";

if(description)
{
  script_id(802358);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2011-4691", "CVE-2011-4692");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:30:25 +0530 (Fri, 09 Dec 2011)");
  script_name("Google Chrome Cache History Information Disclosure Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47127");
  script_xref(name : "URL" , value : "http://lcamtuf.coredump.cx/cachetime/");
  script_xref(name : "URL" , value : "http://sip.cs.princeton.edu/pub/webtiming.pdf");

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

## Check for Google Chrome Version less than 15.0.874.121
if(version_is_less_equal(version:chromeVer, test_version:"15.0.874.121")){
  security_warning(0);
}
