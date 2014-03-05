###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_firefox_iframe_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Firefox 'IFRAME' Denial Of Service vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Firefox version 3.0.x prior to 3.0.19, 3.5.x prior to 3.5.9, 3.6.x prior to 3.6.3";
tag_insight = "The flaw is due to improper handling of 'JavaScript' code which
  contains an infinite loop, that creates IFRAME elements for invalid news://
  or nntp:// URIs.";
tag_solution = "No solution or patch is available as of 02nd Jun, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_id(801347);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-04 09:43:24 +0200 (Fri, 04 Jun 2010)");
  script_cve_id("CVE-2010-2117");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Mozilla Firefox 'IFRAME' Denial Of Service vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://websecurity.com.ua/4238/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511509/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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


include("version_func.inc");

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  # Grep for Firefox version <= 3.0.19, <= 3.5.9, <= 3.6.2
  if(version_in_range(version:ffVer, test_version:"3.5", test_version2:"3.5.9") ||
     version_in_range(version:ffVer, test_version:"3.0", test_version2:"3.0.19") ||
     version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.3")) {
      security_warning(0);
  }
}
