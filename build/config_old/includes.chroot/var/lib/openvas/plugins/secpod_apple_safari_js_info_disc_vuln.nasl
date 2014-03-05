###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apple_safari_js_info_disc_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apple Safari JavaScript Engine Cross Domain Information Disclosure Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in
  the context of the web browser and can spoof sensitive information of the
  remote user through the web browser.
  Impact Level: Application";
tag_affected = "Apple Safari 3.1.2 and prior on Windows.";
tag_insight = "Undefined function in the JavaScript implementation of the browser fails
  to properly enforce the origin policy and leaves temporary footprints.";
tag_solution = "Upgrade to Apple Safari version 5.0 or later
  For updates refer to http://www.apple.com/support/downloads";
tag_summary = "The host is running Apple Safari web browser which is prone
  to information disclosure vulnerability.";

if(description)
{
  script_id(900075);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-01-23 16:33:16 +0100 (Fri, 23 Jan 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-5914");
  script_bugtraq_id(33276);
  script_name("Apple Safari JavaScript Engine Cross Domain Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.trusteer.com/files/In-session-phishing-advisory-2.pdf");

  script_description(desc);
  script_summary("Check for the version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
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

safariVer = get_kb_item("AppleSafari/Version");
if(!safariVer){
  exit(0);
}

if(version_is_less_equal(version:safariVer, test_version:"3.525.21.0")){
  security_warning(0);
}
