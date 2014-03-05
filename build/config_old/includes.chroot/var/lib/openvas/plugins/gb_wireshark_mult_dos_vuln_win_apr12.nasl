###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_win_apr12.nasl 12 2013-10-27 11:15:33Z jan $
#
# Wireshark Multiple Denial of Service Vulnerabilities - April 12 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to cause a denial of
  service.
  Impact Level: Application";
tag_affected = "Wireshark versions 1.4.x before 1.4.12 and 1.6.x before 1.6.6 on Windows";
tag_insight = "The flaws are due to
  - A NULL pointer dereference error in the ANSI A dissector can be exploited
    to cause a crash via a specially crafted packet.
  - An error in the MP2T dissector when allocating memory can be exploited to
    cause a crash via a specially crafted packet.
  - An error exists in the pcap and pcap-ng file parsers when reading ERF data
    and can cause a crash via a specially crafted trace file.";
tag_solution = "Upgrade to the Wireshark version 1.4.12, 1.6.6 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_id(802759);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1596", "CVE-2012-1595", "CVE-2012-1593");
  script_bugtraq_id(52736, 52737, 52735);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-04-23 18:44:30 +0530 (Mon, 23 Apr 2012)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities - April 12 (Windows)");
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


  script_description(desc);
  script_summary("Check for the version of Wireshark on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_require_keys("Wireshark/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-07.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-06.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-04.html");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2012/03/28/13");
  script_xref(name : "URL" , value : "http://anonsvn.wireshark.org/viewvc?view=revision&amp;revision=41001");
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
if(version_in_range (version:sharkVer, test_version:"1.4.0", test_version2:"1.4.11") ||
   version_in_range (version:sharkVer, test_version:"1.6.0", test_version2:"1.6.5")) {
  security_warning(0);
}
