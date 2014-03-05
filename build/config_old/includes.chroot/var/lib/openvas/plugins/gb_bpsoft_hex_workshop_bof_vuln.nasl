###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bpsoft_hex_workshop_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# BreakPoint Software, Hex Workshop Buffer Overflow vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary
  code and can cause denial-of-service.
  Impact Level: Application";
tag_affected = "BreakPoint Software, Hex Workshop version 6.0.1.4603 and prior on Windows.";
tag_insight = "Application fails to adequately sanitize user input data, which in turn
  leads to boundary error while processing of Intel .hex files.";
tag_solution = "No solution or patch is available as of 09th March, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.bpsoft.com/downloads";
tag_summary = "This host has Hex Workshop installed and is prone to Stack
  based Buffer Overflow vulnerability.";

if(description)
{
  script_id(800528);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-10 11:59:23 +0100 (Tue, 10 Mar 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0812");
  script_bugtraq_id(33932);
  script_name("BreakPoint Software, Hex Workshop Buffer Overflow vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34021");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/8121");

  script_description(desc);
  script_summary("Check for the Version of Hex Workshop");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_bpsoft_hex_workshop_detect.nasl");
  script_require_keys("BPSoft/HexWorkshop/Ver");
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

hwVer = get_kb_item("BPSoft/HexWorkshop/Ver");
if(!hwVer){
  exit(0);
}

if(version_is_less_equal(version:hwVer, test_version:"6.0.1.4603")){
  security_hole(0);
}
