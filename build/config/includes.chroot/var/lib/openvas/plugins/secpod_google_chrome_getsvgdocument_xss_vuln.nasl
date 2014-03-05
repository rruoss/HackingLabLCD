###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_google_chrome_getsvgdocument_xss_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Google Chrome 'getSVGDocument' Cross-Site Scripting Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to conduct XSS attacks
  on the victim's system via SVG document.
  Impact Level: Application";
tag_affected = "Google Chrome version prior to 3.0.195.21 on Windows.";
tag_insight = "Error exists when 'getSVGDocument' method omits an unspecified access check
  which can be exploited by remote web servers to bypass the Same Origin
  Policy and conduct XSS attacks via unknown vectors.";
tag_solution = "Upgrade to Google Chrom version 3.0.195.21 or later
  http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to Cross-Site
  Scripting vulnerability.";

if(description)
{
  script_id(900860);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-23 08:37:26 +0200 (Wed, 23 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3264");
  script_bugtraq_id(36416);
  script_name("Google Chrome 'getSVGDocument' Cross-Site Scripting Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36770");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=21338");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.com/2009/09/stable-channel-update.html");

  script_description(desc);
  script_summary("Check for the version of Google Chrome");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
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

chromeVer = get_kb_item("GoogleChrome/Win/Ver");
if(!chromeVer){
  exit(0);
}

# Check for Google Chrome version < 3.0.195.21
if(version_is_less(version:chromeVer, test_version:"3.0.195.21")){
  security_warning(0);
}
