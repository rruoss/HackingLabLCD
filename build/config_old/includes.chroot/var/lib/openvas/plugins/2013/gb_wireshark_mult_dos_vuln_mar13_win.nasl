###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_dos_vuln_mar13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wireshark Multiple Dissector Multiple DoS Vulnerabilities - March 13 (Windows)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to cause denial of
  service or to consume excessive CPU resources.
  Impact Level: Application";

tag_affected = "Wireshark 1.6.x before 1.6.14, 1.8.x before 1.8.6 on Windows";
tag_insight = "Multiple flaws are due to errors in MS-MMS, RTPS, RTPS2, Mount, AMPQ, ACN,
  CIMD, FCSP and DTLS dissectors.";
tag_solution = "Upgrade to the Wireshark version 1.6.14 or 1.8.6 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  denial of service vulnerabilities.";

if(description)
{
  script_id(803330);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2478", "CVE-2013-2480", "CVE-2013-2481", "CVE-2013-2482",
                "CVE-2013-2483", "CVE-2013-2484", "CVE-2013-2485", "CVE-2013-2488");
  script_bugtraq_id(58357, 58351, 58340, 58353, 58355, 58356, 58362, 58365);
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:57:44 +0530 (Mon, 11 Mar 2013)");
  script_name("Wireshark Multiple Dissector Multiple DoS Vulnerabilities - March 13 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52471");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1028254");
  script_xref(name : "URL" , value : "http://www.wireshark.org/docs/relnotes/wireshark-1.8.6.html");

  script_description(desc);
  script_summary("Check for the vulnerable version of Wireshark on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
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

if(sharkVer && sharkVer=~ "^(1.6|1.8)")
{
  ## Check for vulnerable Wireshark versions
  if(version_in_range(version:sharkVer, test_version:"1.6.0", test_version2:"1.6.13") ||
     version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.5")){
    security_hole(0);
    exit(0);
  }
}
