###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_sep12_lin01.nasl 12 2013-10-27 11:15:33Z jan $
#
# Google Chrome Multiple Vulnerabilities - Sep12 (Linux-01)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow the attackers to conduct cross-site
  scripting attacks, bypass certain security restrictions, cause
  denial-of-service conditions and other attacks are also possible.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 22.0.1229.79 on Linux";
tag_insight = "For more information on the vulnerabilities refer to the links below.";
tag_solution = "Upgrade to the Google Chrome 22.0.1229.79 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802973);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2888", "CVE-2012-2887", "CVE-2012-2886", "CVE-2012-2885",
                "CVE-2012-2884", "CVE-2012-2883", "CVE-2012-2882", "CVE-2012-2881",
                "CVE-2012-2880", "CVE-2012-2879", "CVE-2012-2878", "CVE-2012-2877",
                "CVE-2012-2876", "CVE-2012-2875", "CVE-2012-2889", "CVE-2012-2890",
                "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2893", "CVE-2012-2894",
                "CVE-2012-2895", "CVE-2012-2874");
  script_bugtraq_id(55676);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-28 12:49:03 +0530 (Fri, 28 Sep 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - Sep12 (Linux-01)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50759/");
  script_xref(name : "URL" , value : "https://code.google.com/p/chromium/issues/detail?id=137852");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome on Linux");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_require_keys("Google-Chrome/Linux/Ver");
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

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 22.0.1229.79
if(version_is_less(version:chromeVer, test_version:"22.0.1229.79")){
  security_hole(0);
}
