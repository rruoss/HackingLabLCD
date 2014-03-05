###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_jul13_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Google Chrome Multiple Vulnerabilities-01 July13 (MAC OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "
  Impact Level: System/Application";

if(description)
{
  script_id(803903);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2880", "CVE-2013-2879", "CVE-2013-2878", "CVE-2013-2877",
                "CVE-2013-2876", "CVE-2013-2875", "CVE-2013-2873", "CVE-2013-2872",
                "CVE-2013-2871", "CVE-2013-2870", "CVE-2013-2869", "CVE-2013-2868",
                "CVE-2013-2868", "CVE-2013-2867", "CVE-2013-2853");
  script_bugtraq_id(61046, 61052, 61055, 61047, 61059, 61061, 61057, 61051, 61056,
                    61060, 61053, 61054, 61058, 61050, 61049);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-16 19:10:22 +0530 (Tue, 16 Jul 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 July13 (MAC OS X)");

  tag_summary =
"The host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_insight =
"Multiple flaws due to,
 - Error exists when setting up sign-in and sync operations.
 - An out-of-bounds read error exists within text handling.
 - 'parser.c in libxml2' has out-of-bounds read error, related to the lack of
   checks for the XML_PARSER_EOF state.
 - 'browser/extensions/api/tabs/tabs_api.cc' does not enforce restrictions on
   the capture of screenshots by extensions.
 - An out-of-bounds read error exists in SVG handling.
 - Unspecified error related to GL textures, only when an Nvidia GPU is used.
 - Unspecified use-after-free vulnerabilities.
 - An out-of-bounds read error exists within JPEG2000 handling.
 - Unspecified error exists within sync of NPAPI extension component.
 - Does not properly prevent pop.
 - HTTPS implementation does not ensure how headers are terminated.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code,
bypass security restrictions, disclose potentially sensitive data, or cause
denial of service condition.";

  tag_affected =
"Google Chrome version prior to 28.0.1500.71 on MAC OS X.";

  tag_solution =
"Upgrade to the Google Chrome 28.0.1500.71 or later,
For updates refer to http://www.google.com/chrome ";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/95089");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54017");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/07/stable-channel-update.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the vulnerable version of Google Chrome on MAC OS X");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");
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

## Check for Google Chrome Version less than 28.0.1500.71
if(version_is_less(version:chromeVer, test_version:"28.0.1500.71"))
{
  security_hole(0);
  exit(0);
}
