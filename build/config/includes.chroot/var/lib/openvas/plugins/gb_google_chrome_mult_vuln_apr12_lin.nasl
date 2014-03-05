###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln_apr12_lin.nasl 12 2013-10-27 11:15:33Z jan $
#
# Google Chrome Multiple Vulnerabilities - April 12 (Linux)
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
tag_impact = "Successful exploitation could allow attackers to inject scripts, bypass
  certain security restrictions, execute arbitrary code in the context of the
  browser or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 18.0.1025.142 on Linux";
tag_insight = "The flaws are due to
  - An error while handling the EUC-JP encoding system, may allow cross-site
    scripting attacks.
  - An unspecified error in Skia can be exploited to corrupt memory.
  - A use-after-free error exists in SVG clipping.
  - A validation error exists within the handling of certain navigation
    requests from the renderer.
  - An off-by-one error exists in OpenType sanitizer.
  - An error exists within SPDY proxy certificate checking.
  - An error in text fragment handling can be exploited to cause an
    out-of-bounds read.
  - An error in SVG text handling can be exploited to cause an out-of-bounds
    read.";
tag_solution = "Upgrade to the Google Chrome 18.0.1025.142 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802733);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3058", "CVE-2011-3065", "CVE-2011-3064", "CVE-2011-3063",
                "CVE-2011-3062", "CVE-2011-3061", "CVE-2011-3060", "CVE-2011-3059");
  script_bugtraq_id(52762);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-05 15:48:59 +0530 (Thu, 05 Apr 2012)");
  script_name("Google Chrome Multiple Vulnerabilities - April 12 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48618/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026877");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/03/stable-channel-release-and-beta-channel.html");

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

## Check for Google Chrome Versions prior to 18.0.1025.142
if(version_is_less(version:chromeVer, test_version:"18.0.1025.142")){
  security_hole(0);
}
