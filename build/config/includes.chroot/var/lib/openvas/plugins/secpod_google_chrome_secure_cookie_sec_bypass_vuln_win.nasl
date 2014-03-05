###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_secure_cookie_sec_bypass_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Chrome Secure Cookie Security Bypass Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to overwrite or delete arbitrary
  cookies by sending a specially crafted HTTP response through a man-in-the-
  middle attack.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 4.0.211.0 on Windows.";
tag_insight = "The flaw is due to improper restrictions for modifications to cookies
  established in HTTPS sessions i.e lack of the HTTP Strict Transport Security
  (HSTS) includeSubDomains feature, which allows man-in-the-middle attackers
  to overwrite or delete arbitrary cookies via a Set-Cookie header in an HTTP
  response.";
tag_solution = "Upgrade to the Google Chrome 4.0.211.0 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to security bypass
  vulnerability.";

if(description)
{
  script_id(902614);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-19 15:17:22 +0200 (Fri, 19 Aug 2011)");
  script_cve_id("CVE-2008-7294");
  script_bugtraq_id(49133);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Google Chrome Secure Cookie Security Bypass Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/show/osvdb/74449");
  script_xref(name : "URL" , value : "http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_cookies");
  script_xref(name : "URL" , value : "http://michael-coates.blogspot.com/2010/01/cookie-forcing-trust-your-cookies-no.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 SecPod");
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

## Check for Google Chrome Version less than 4.0.211.0
if(version_is_less(version:chromeVer, test_version:"4.0.211.0")){
  security_hole(0);
}
