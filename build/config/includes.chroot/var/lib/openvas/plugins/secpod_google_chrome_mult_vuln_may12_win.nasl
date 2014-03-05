###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_may12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Google Chrome Multiple Vulnerabilities(02) - May 12 (Windows)
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
tag_impact = "Successful exploitation could allow attackers to bypass certain security
  restrictions,  execute arbitrary code in the context of the browser or
  cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Google Chrome version prior to 19.0.1084.52 on Windows";
tag_insight = "The flaws are due to
  - An unspecified error exists in the v8 garbage collection, plug-in
    JavaScript bindings.
  - A use-after-free error exists in the browser cache, first-letter handling
    and with encrypted PDF.
  - An out-of-bounds read error exists in Skia.
  - An error with websockets over SSL can be exploited to corrupt memory.
  - An invalid read error exists in v8.
  - An invalid cast error exists with colorspace handling in PDF.
  - An error with PDF functions can be exploited to cause a buffer overflow.
  - A type corruption error exists in v8.";
tag_solution = "Upgrade to the Google Chrome 19.0.1084.52 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(903030);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3103", "CVE-2011-3104", "CVE-2011-3105", "CVE-2011-3106",
                "CVE-2011-3107", "CVE-2011-3108", "CVE-2011-3110", "CVE-2011-3111",
                "CVE-2011-3112", "CVE-2011-3113", "CVE-2011-3114", "CVE-2011-3115");
  script_bugtraq_id(53679);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-25 14:51:26 +0530 (Fri, 25 May 2012)");
  script_name("Google Chrome Multiple Vulnerabilities(02) - May 12 (Windows)");
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


  script_description(desc);
  script_copyright("Copyright (C) 2012 SecPod");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49277/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027098");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2012/05/stable-channel-update_23.html");
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

## Check for Google Chrome Versions prior to 19.0.1084.52
if(version_is_less(version:chromeVer, test_version:"19.0.1084.52")){
  security_hole(0);
}
