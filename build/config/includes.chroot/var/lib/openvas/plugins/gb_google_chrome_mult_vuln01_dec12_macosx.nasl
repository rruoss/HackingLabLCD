###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_dec12_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Google Chrome Multiple Vulnerabilities-01 Dec2012 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 23.0.1271.91 on Mac OS X";
tag_insight = "- An out-of-bounds read error exists in Skia.
  - A use-after-free error exists in SVG filters and in within printing.
  - Heap-based buffer underflow in the xmlParseAttValueComplex function in
    parser.c in libxmlier, allows remote attackers to cause a denial of service
    or possibly execute arbitrary code via crafted entities in an XML document.
  - A bad cast error exists within input element handling.
  - Browser crash with chunked encoding.
  - Does not properly mitigate improper rendering behavior in the Intel GPU
    driver, which allows remote attackers to cause a denial of service";
tag_solution = "Upgrade to the Google Chrome 23.0.1271.91 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803120);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5130", "CVE-2012-5131", "CVE-2012-5132", "CVE-2012-5133",
                "CVE-2012-5134", "CVE-2012-5135", "CVE-2012-5136");
  script_bugtraq_id(56684);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-12-04 11:48:25 +0530 (Tue, 04 Dec 2012)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Dec2012 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51437/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/11/stable-channel-update.html");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_require_keys("GoogleChrome/MacOSX/Version");
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
chromeVer = get_kb_item("GoogleChrome/MacOSX/Version");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 23.0.1271.91
if(version_is_less(version:chromeVer, test_version:"23.0.1271.91")){
  security_hole(0);
}
