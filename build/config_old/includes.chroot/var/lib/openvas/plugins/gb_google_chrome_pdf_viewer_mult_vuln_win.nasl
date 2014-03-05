###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_pdf_viewer_mult_vuln_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Google Chrome PDF Viewer Multiple Vulnerabilities (Windows)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 21.0.1180.75 on Windows";
tag_insight = "A use-after-free and out-of-bounds write errors exists within the PDF viewer.";
tag_solution = "Upgrade to the Google Chrome 21.0.1180.75 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to use after
  free and denial of service vulnerabilities.";

if(description)
{
  script_id(802932);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2862", "CVE-2012-2863");
  script_bugtraq_id(54897);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-14 17:03:39 +0530 (Tue, 14 Aug 2012)");
  script_name("Google Chrome PDF Viewer Multiple Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50222/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/08/stable-channel-update.html");

  script_description(desc);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome on Windows");
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

## Variable Initialization
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 21.0.1180.75
if(version_is_less(version:chromeVer, test_version:"21.0.1180.75")){
  security_hole(0);
}
