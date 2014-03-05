###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_lua_script_code_exec_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Wireshark Lua Script File Arbitrary Code Execution Vulnerability (Windows)
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
tag_impact = "Successful exploitation will allow the attacker to execute arbitrary Lua
  script in the context of the affected application.
  Impact Level: System/Application";
tag_affected = "Wireshark versions 1.4.x before 1.4.9 and 1.6.x before 1.6.2.";
tag_insight = "The flaw is due to an unspecified error related to Lua scripts, which
  allows local users to gain privileges via a Trojan horse Lua script in an
  unspecified directory.";
tag_solution = "Upgrade to the Wireshark version 1.4.9, 1.6.2 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to code
  execution vulnerability.";

if(description)
{
  script_id(802249);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_bugtraq_id(49528);
  script_cve_id("CVE-2011-3360");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Wireshark Lua Script File Arbitrary Code Execution Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/75347");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-15.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=6136");

  script_description(desc);
  script_summary("Check for the version of Wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
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

## Variable Initialization
sharkVer = "";

## Get version from KB
sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.1") ||
   version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.8")) {
  security_hole(0);
}
