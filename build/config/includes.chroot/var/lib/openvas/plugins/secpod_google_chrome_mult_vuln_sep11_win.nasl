###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_sep11_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Chrome Multiple Vulnerabilities - Sep11 (Win)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser, inject scripts, bypass certain security
  restrictions, or cause a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 14.0.835.163 on Windows.";
tag_insight = "For more information on the vulnerabilities refer to the links below.";
tag_solution = "Upgrade to the Google Chrome 14.0.835.163 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902627);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_cve_id("CVE-2011-2834", "CVE-2011-2835", "CVE-2011-2836", "CVE-2011-2838",
                "CVE-2011-2839", "CVE-2011-2840", "CVE-2011-2841", "CVE-2011-2843",
                "CVE-2011-2844", "CVE-2011-2846", "CVE-2011-2847", "CVE-2011-2848",
                "CVE-2011-2849", "CVE-2011-2850", "CVE-2011-2851", "CVE-2011-2852",
                "CVE-2011-2853", "CVE-2011-2854", "CVE-2011-2855", "CVE-2011-2856",
                "CVE-2011-2857", "CVE-2011-2858", "CVE-2011-2859", "CVE-2011-2860",
                "CVE-2011-2861", "CVE-2011-2862", "CVE-2011-2864", "CVE-2011-2874",
                "CVE-2011-2875", "CVE-2011-3234", "CVE-2011-2830");
  script_bugtraq_id(49658);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Google Chrome Multiple Vulnerabilities - Sep11 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46049");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/09/stable-channel-update_16.html");

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

## Check for Google Chrome Version less than 14.0.835.163
if(version_is_less(version:chromeVer, test_version:"14.0.835.163")){
  security_hole(0);
}
