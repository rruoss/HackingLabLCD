###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_may13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wireshark Multiple Dissector Multiple Vulnerabilities - May 13 (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to crash the
  application, resulting in denial of service condition.
  Impact Level: Application";

tag_affected = "Wireshark versions 1.8.x before 1.8.7 on Windows";
tag_insight = "Multiple flaws are due to errors in Websocket, MySQL, ETCH, MPEG DSM-CC,
  DCP ETSI, PPP CCP and GTPv2 dissectors.";
tag_solution = "Upgrade to the Wireshark version 1.8.7 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803620);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3562", "CVE-2013-3561", "CVE-2013-3560", "CVE-2013-3559",
                "CVE-2013-3558", "CVE-2013-3555");
  script_bugtraq_id(59998, 60002, 59996, 60001, 59999, 60000, 59995, 60003, 59994,
                    59992);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-28 15:30:37 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark Multiple Dissector Multiple Vulnerabilities - May 13 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.com/93503");
  script_xref(name : "URL" , value : "http://www.osvdb.com/93504");
  script_xref(name : "URL" , value : "http://www.osvdb.com/93505");
  script_xref(name : "URL" , value : "http://www.osvdb.com/93506");
  script_xref(name : "URL" , value : "http://www.osvdb.com/93507");
  script_xref(name : "URL" , value : "http://www.osvdb.com/93508");
  script_xref(name : "URL" , value : "http://www.osvdb.com/93510");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53425");
  script_xref(name : "URL" , value : "http://www.wireshark.org/docs/relnotes/wireshark-1.8.7.html");
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
if(sharkVer && sharkVer=~ "^1.8")
{
  ## Check for vulnerable Wireshark versions
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.6")){
    security_hole(0);
    exit(0);
  }
}
