###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_js_impl_info_disc_vuln_macosx.nasl 13 2013-10-27 12:16:33Z jan $
#
# Apple Safari JavaScript Implementation Information Disclosure Vulnerability (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to gain access to sensitive
  information and launch other attacks.
  Impact Level: Application";
tag_affected = "Apple Safari version 4";
tag_insight = "The flaw is due to the JavaScript implementation is not properly
  restrict the set of values contained in the object returned by the
  getComputedStyle method, which allows remote attackers to obtain sensitive
  information about visited web pages.";
tag_solution = "No solution or patch is available as of 09th December, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.apple.com/safari/download/";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to information disclosure vulnerability.";

if(description)
{
  script_id(802285);
  script_version("$Revision: 13 $");
  script_cve_id("CVE-2010-5070");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-12-09 12:12:12 +0530 (Fri, 09 Dec 2011)");
  script_name("Apple Safari JavaScript Implementation Information Disclosure Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://w2spconf.com/2010/papers/p26.pdf");

  script_description(desc);
  script_summary("Check for the version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_require_keys("AppleSafari/MacOSX/Version");
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

safVer = get_kb_item("AppleSafari/MacOSX/Version");
if(!safVer){
  exit(0);
}

## Grep for Apple Safari Version 4
if(version_in_range(version:safVer,test_version:"4.0",test_version2:"4.1.3")){
  security_warning(0);
}
