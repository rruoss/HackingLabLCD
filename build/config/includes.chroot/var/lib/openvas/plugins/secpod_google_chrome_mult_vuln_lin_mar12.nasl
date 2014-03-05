###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_lin_mar12.nasl 12 2013-10-27 11:15:33Z jan $
#
# Google Chrome Multiple Vulnerabilities (Linux) - Mar 12
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code,
  cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 17.0.963.83 on Linux";
tag_insight = "The flaws are due to
  - Not properly restrict the extension web request API.
  - Memory corruption in WebGL canvas handling.
  - Use-after-free in block splitting.
  - An error in WebUI privilege implementation which fails to properly perform
    isolation.
  - Prompt in the browser native UI for unpacked extension installation.
  - Cross-origin violation with magic iframe.
  - An invalid read error exists within v8.
  - A use-after-free error exists when handling CSS cross-fade.
  - A use-after-free error exists when handling the first letter.
  - An error exists in the bundled version of libpng.";
tag_solution = "Upgrade to Google Chrome version 17.0.963.83 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(903005);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3049", "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054",
                "CVE-2011-3055", "CVE-2011-3056", "CVE-2011-3057", "CVE-2011-3051",
                "CVE-2011-3050", "CVE-2011-3045");
  script_bugtraq_id(52674);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-26 16:40:40 +0530 (Mon, 26 Mar 2012)");
  script_name("Google Chrome Multiple Vulnerabilities (Linux) - Mar 12");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48512/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026841");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/03/stable-channel-update_21.html");

  script_description(desc);
  script_summary("Check for the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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

## Check for Google Chrome version < 17.0.963.83
if(version_is_less(version:chromeVer, test_version:"17.0.963.83")){
  security_hole(0);
}
