###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_js_uri_xss_vuln_sep09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Google Chrome 'javascript: URI' XSS Vulnerability - Sep09
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to conduct Cross-Site Scripting
  attacks in the victim's system.
  Impact Level: Application";
tag_affected = "Google Chrome version 1.0.154.48 and prior, 2.0.172.28 and 2.0.172.37,
                    and 3.0.193.2 Beta on Windows.";
tag_insight = "Google Chrome fails to sanitise the 'javascript:' and 'data:' URIs in Refresh
  headers in HTTP responses, which can be exploited via vectors related to
  injecting a Refresh header.";
tag_solution = "No solution or patch is available as of 03nd September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome Web Browser and is prone
  to Cross-Site Scripting vulnerability.";

if(description)
{
  script_id(800881);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3011");
  script_name("Google Chrome 'javascript: URI' XSS Vulnerability - Sep09");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/3315/");

  script_description(desc);
  script_summary("Check for the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(isnull(chromeVer))
{
  exit(0);
}

# Check for Google Chrome Version <= 1.0.154.48,2.0.172.28, 2.0.172.37
#                                and 3.0.193.2 Beta
if(version_is_less_equal(version:chromeVer, test_version:"1.0.154.48")||
   version_is_equal(version:chromeVer, test_version:"2.0.172.37")||
   version_is_equal(version:chromeVer, test_version:"2.0.172.28")||
   version_is_equal(version:chromeVer, test_version:"3.0.193.2")){
   security_warning(0);
}
