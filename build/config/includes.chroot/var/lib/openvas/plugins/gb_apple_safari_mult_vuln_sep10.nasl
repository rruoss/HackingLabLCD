###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_mult_vuln_sep10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Apple Safari Multiple Vulnerabilities - Sep10
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allow attackers to execute arbitrary code or can
  even crash the browser.
  Impact Level: Application";
tag_affected = "Apple Safari 5.x before 5.0.2 on Windows";
tag_insight = "The flaws are due to
  - An use-after-free vulnerability in the application, which allows remote
    attackers to execute arbitrary code via 'run-in' styling in an element,
    related to object pointers.
  - An untrusted search path vulnerability on Windows allows local users
    to gain privileges via a Trojan horse 'explorer.exe'.
  - An error exists in the handling of 'WebKit', which does not properly
    validate floating-point data, which allows remote attackers to execute
    arbitrary cod via a crafted HTML document.";
tag_solution = "Upgrade Apple Safari 5.0.2 or later,
  For updates refer to http://www.apple.com/support/downloads/";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(801514);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-1805", "CVE-2010-1806", "CVE-2010-1807");
  script_bugtraq_id(43049, 43048, 43047);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Apple Safari Multiple Vulnerabilities - Sep10");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT4333");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2010//Sep/msg00001.html");

  script_description(desc);
  script_summary("Check for the version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
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

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

# Grep for Apple Safari Version 5.x < 5.0.2((5.33.18.5)
if(version_in_range(version:safVer, test_version:"5.0", test_version2:"5.33.18.4")){
  security_hole(0);
}
