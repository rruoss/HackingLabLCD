###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_getwidget_dos_vuln_lin.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Chrome 'GetWidget' methods DoS Vulnerability (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow the attackers to cause denial-of-service
  via a crafted web site, related to GetWidget methods.
  Impact Level: Application";
tag_affected = "Google Chrome version 14.0.792.0";
tag_insight = "The flaw is due to error while handling a reload of a page generated
  in response to a POST which allows remote attackers to cause a denial of
  service.";
tag_solution = "Upgrade to the Google Chrome 14.0.794.0 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed Google Chrome and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(802127);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2011-2761");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Google Chrome 'GetWidget' methods DoS Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://codereview.chromium.org/7189019");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=86119");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2011/06/dev-channel-update_16.html");

  script_description(desc);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
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

## Check for Google Chrome Version equal to 14.0.792.0
if(version_is_equal(version:chromeVer, test_version:"14.0.792.0")){
  security_warning(0);
}