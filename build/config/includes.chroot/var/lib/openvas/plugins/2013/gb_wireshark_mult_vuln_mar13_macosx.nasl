###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_mar13_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wireshark Multiple Dissector Multiple Vulnerabilities - March 13 (Mac OS X)
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

tag_affected = "Wireshark versions 1.8.x before 1.8.6 on Mac OS X";
tag_insight = "Multiple flaws are due to errors in RELOAD, MPLS Echo, CSN.1, HART/IP and TCP
  dissectors.";
tag_solution = "Upgrade to the Wireshark version 1.8.6 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803333);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-2479", "CVE-2013-2477",
                "CVE-2013-2476", "CVE-2013-2475");
  script_bugtraq_id(58363,58350,58354,58358,58349,58364);
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:11 +0530 (Mon, 11 Mar 2013)");
  script_name("Wireshark Multiple Dissector Multiple Vulnerabilities - March 13 (Mac OS X)");
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
  script_summary("Check for the vulnerable version of Wireshark on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
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

if(sharkVer && sharkVer=~ "^1.8")
{
  ## Check for vulnerable Wireshark versions
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.5")){
    security_hole(0);
    exit(0);
  }
}