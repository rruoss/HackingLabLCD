###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_xss_vuln_may09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Google Chrome Multilpe XSS Vulnerabilities (May 09)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes and
  XSS attack in the context of the web browser.";
tag_affected = "Google Chrome versions prior to 1.0.154.59.";
tag_insight = "- Error in chromeHTML URL protocol handler, that do not satisfy the
    IsWebSafeScheme restriction via a web page that sets document.location
    and also that are not constructed with sufficient escaping hence when
    invoked by Internet Explorer might open multiple tabs for unconstrained
    protocols such as javascript: or file:.
  - It may allow malicious URLs to bypass the same-origin policy and
    obtain sensitive information including authentication credentials.";
tag_solution = "Upgrade to Google Chrome version 1.0.154.59.
  http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to
  multiple XSS vulnerabilities.";

if(description)
{
  script_id(800561);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-07 14:39:04 +0200 (Thu, 07 May 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-1412", "CVE-2009-1340");
  script_bugtraq_id(34704);
  script_name("Google Chrome Multilpe XSS Vulnerabilities (May 09)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34900");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=9860");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2009/04/stable-update-security-fix.html");

  script_description(desc);
  script_summary("Check for the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
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
if(!chromeVer){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"1.0.154.59")){
  security_hole(0);
}
