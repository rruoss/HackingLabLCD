###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_mult_vuln_sep10_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Google Chrome multiple vulnerabilities Sep-10 (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2010-09-28
#  Added the related CVE
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow the attackers to cause denial of service
  and possibly have unspecified other impact via unknown vectors.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 6.0.472.59 on Linux.";
tag_insight = "Multiple vulnerabilities are due to,
  - A use-after-free error exists when using document APIs during parsing.
  - A use-after-free error exists in the processing of SVG styles.
  - A use-after-free error exists in the processing of nested SVG elements.
  - An assert error exists related to cursor handling.
  - A race condition exists in the console handling.
  - An unspecified error exists in the pop-up blocking functionality.
  - An unspecified error related to Geolocation can be exploited to corrupt memory.
  - An unspecified error related to Khmer handling can be exploited to corrupt memory.
  - The application does not prompt for extension history access.";
tag_solution = "Upgrade to the Google Chrome 6.0.472.59 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(901154);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-21 16:43:08 +0200 (Tue, 21 Sep 2010)");
  script_cve_id("CVE-2010-1825", "CVE-2010-1824", "CVE-2010-1823",
                "CVE-2010-3411", "CVE-2010-3412", "CVE-2010-3413",
                "CVE-2010-3415", "CVE-2010-3416", "CVE-2010-3417",
                "CVE-2010-1823", "CVE-2010-1824", "CVE-2010-1825");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Google Chrome multiple vulnerabilities Sep-10 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41390/");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2010/09/stable-beta-channel-updates_14.html");

  script_description(desc);
  script_copyright("Copyright (C) 2010 SecPod");
  script_summary("Check the version of Google Chrome");
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

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 6.0.472.59
if(version_is_less(version:chromeVer, test_version:"6.0.472.59")){
  security_hole(0);
}
