###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_mult_vuln_feb10_lin.nasl 14 2013-10-27 12:33:37Z jan $
#
# Firefox Multiple Vulnerabilities Feb-10 (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation allows attackers to obtain sensitive information via
  a crafted document.
  Impact Level: Application.";
tag_affected = "Firefox version prior to 3.6 on Linux.";
tag_insight = "- The malformed stylesheet document and cross-origin loading of CSS
    stylesheets even when the stylesheet download has an incorrect MIME type.
  - IFRAME element allows placing the site&qts URL in the HREF attribute of a
    stylesheet 'LINK' element, and then reading the 'document.styleSheets[0].href'
    property value.";
tag_solution = "Upgrade to Firefox version 3.6,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Firefox Browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900743);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0648", "CVE-2010-0654");
  script_name("Firefox Multiple Vulnerabilities Feb-10 (Linux)");
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
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=9877");
  script_xref(name : "URL" , value : "http://code.google.com/p/chromium/issues/detail?id=32309");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

# Firefox Check
ffVer = get_kb_item("Firefox/Linux/Ver");
if(isnull(ffVer)){
  exit(0);
}

# Check for Firefox version less than 3.6
if(version_is_less(version:ffVer, test_version:"3.6")){
  security_warning(0);
}
