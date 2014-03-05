###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_use_after_free_vuln_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Chrome Use-After-Free Vulnerability (Linux)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 11.0.672.2 on Linux";
tag_insight = "An use-after-free error in WebCore in WebKit allows user-assisted remote
  attackers to cause a denial of service or possibly have unspecified other
  impact via vectors that entice a user to resubmit a form, related to improper
  handling of provisional items by the HistoryController component.";
tag_solution = "Upgrade to the Google Chrome 11.0.672.2 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is running Google Chrome and is prone to use-after-free
  vulnerability.";

if(description)
{
  script_id(901191);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)");
  script_cve_id("CVE-2011-1059");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Google Chrome Use-After-Free Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "https://bugs.webkit.org/show_bug.cgi?id=52819");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=70315");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/02/dev-channel-update_17.html");

  script_description(desc);
  script_copyright("Copyright (C) 2011 SecPod");
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

## Check for Google Chrome Version less than 11.0.672.2
if(version_is_less(version:chromeVer, test_version:"11.0.672.2")){
  security_warning(0);
}
