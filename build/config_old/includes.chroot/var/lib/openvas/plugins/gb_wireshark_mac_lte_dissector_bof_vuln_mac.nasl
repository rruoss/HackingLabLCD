###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mac_lte_dissector_bof_vuln_mac.nasl 12 2013-10-27 11:15:33Z jan $
#
# Wireshark MAC-LTE dissector Buffer Overflow Vulnerability (Mac OS X)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to create a denial of service
  or execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Wireshark versions 1.2.0 through 1.2.13 and 1.4.0 through 1.4.2 on Mac OS X";
tag_insight = "The flaw is caused by a buffer overflow error in the MAC-LTE dissector,
  which could be exploited to crash an affected application or compromise
  a vulnerable system.";
tag_solution = "Upgrade to the latest version of Wireshark 1.4.3 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to buffer
  overflow vulnerability.";

if(description)
{
  script_id(802664);
  script_version("$Revision: 12 $");
  script_bugtraq_id(45775);
  script_cve_id("CVE-2011-0444");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-30 17:17:17 +0530 (Mon, 30 Jul 2012)");
  script_name("Wireshark MAC-LTE dissector Buffer Overflow Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/70403");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64624");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0079");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2011-02.html");
  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5530");

  script_description(desc);
  script_summary("Check for the version of Wireshark on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_require_keys("Wireshark/MacOSX/Version");
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
sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

## Check for vulnerable Wireshark versions
if(version_in_range (version:sharkVer, test_version:"1.2.0", test_version2:"1.2.13") ||
   version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.2")) {
  security_hole(0);
}
