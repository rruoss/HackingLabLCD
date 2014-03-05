###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_lin_jun11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Chrome Multiple Vulnerabilities (Linux) - June 11
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service, cross-site-scripting and execution of arbitrary code.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 12.0.742.112 on Linux.";
tag_insight = "The flaws are due to:
  - Error in 'NPAPI implementation', while handling the strings.
  - Use-after-free error in SVG font handling.
  - Memory corruption error while handling 'Cascading Style Sheets (CSS)'
    token sequences.
  - Incorrect bounds check in Google V8.
  - Use-after-free vulnerability, allows attackers to cause denial of service
    via vectors related to text selection.
  - Error in 'HTML' parser, while handling the address 'lifetime and
    re-entrancy issues'.
  - Use-after-free error with 'SVG' use element.";
tag_solution = "Upgrade to Google Chrome version 12.0.742.112 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902393);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-01 16:09:45 +0200 (Fri, 01 Jul 2011)");
  script_cve_id("CVE-2011-2345", "CVE-2011-2346", "CVE-2011-2347", "CVE-2011-2348",
                "CVE-2011-2349", "CVE-2011-2350", "CVE-2011-2351");
  script_bugtraq_id(48479);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Google Chrome Multiple Vulnerabilities (Linux) - June 11");
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
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/06/stable-channel-update_28.html");

  script_description(desc);
  script_summary("Check for the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome version < 12.0.742.112
if(version_is_less(version:chromeVer, test_version:"12.0.742.112")){
  security_hole(0);
}
