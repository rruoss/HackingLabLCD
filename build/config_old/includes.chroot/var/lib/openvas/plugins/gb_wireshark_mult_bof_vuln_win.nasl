###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_bof_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Wireshark Multiple Buffer Overflow Vulnerabilities (Win)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation allows attackers to crash an affected application or
  potentially execute arbitrary code.
  Impact Level: Application.";
tag_affected = "Wireshark version 1.2.0 to 1.2.5 and 0.9.15 to 1.0.10";
tag_insight = "The flaws are caused by buffer overflow errors in the LWRES dissector when
  processing malformed data or packets.";
tag_solution = "Upgrade to Wireshark 1.2.6 or 1.0.11
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to multiple Buffer
  Overflow vulnerabilities.";

if(description)
{
  script_id(800290);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-08 10:53:20 +0100 (Mon, 08 Feb 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0304");
  script_bugtraq_id(37985);
  script_name("Wireshark Multiple Buffer Overflow Vulnerabilities (Win)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55951");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37985/info");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0239");

  script_description(desc);
  script_summary("Check for the version of Wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_family("Buffer overflow");
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

wireVer = get_kb_item("Wireshark/Win/Ver");
if(!wireVer){
  exit(0);
}

if(version_in_range(version:wireVer, test_version:"1.2.0", test_version2:"1.2.5") ||
   version_in_range(version:wireVer, test_version:"0.9.15", test_version2:"1.0.10")){
  security_hole(0);
}
