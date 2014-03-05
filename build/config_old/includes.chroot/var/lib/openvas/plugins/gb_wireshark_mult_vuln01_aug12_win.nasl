###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln01_aug12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Wireshark Multiple Vulnerabilities(01) - August 2012 (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  in the context of the application, crash affected application or to consume
  excessive CPU resources.
  Impact Level: System/Application";
tag_affected = "Wireshark 1.8.x before 1.8.2 on Windows";
tag_insight = "The flaws are due to
  - An error within the pcap-ng file parser, Ixia IxVeriWave file parser and
    ERF dissector can be exploited to cause a buffer overflow.
  - An error within the MongoDB dissector can be exploited to trigger an
    infinite loop and consume excessive CPU resources.";
tag_solution = "Upgrade to the Wireshark version 1.8.2 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802945);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4298", "CVE-2012-4295", "CVE-2012-4294", "CVE-2012-4287",
                "CVE-2012-4286");
  script_bugtraq_id(55035);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-21 14:03:40 +0530 (Tue, 21 Aug 2012)");
  script_name("Wireshark Multiple Vulnerabilities(01) - August 2012 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50276/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027404");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-25.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-16.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-14.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2012-24.html");

  script_description(desc);
  script_summary("Check for the version of Wireshark on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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
if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.1")) {
  security_hole(0);
}
