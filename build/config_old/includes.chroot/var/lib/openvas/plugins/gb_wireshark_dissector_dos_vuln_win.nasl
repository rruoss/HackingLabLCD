###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dissector_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Wireshark 'packet-gsm_a_rr.c' Denial of Service Vulnerability (Win)
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
tag_impact = "Successful exploitation could allow attackers to cause a denial of service.
  Impact Level: Application";
tag_affected = "Wireshark version 1.2.2 through 1.2.9";
tag_insight = "The flaw is due to an error in 'packet-gsm_a_rr.c' in the GSM A RR
  dissector.";
tag_solution = "Upgrade to the Wireshark version 1.2.10 or later,
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "The host is installed with Wireshark and is prone to Denial of
  Service Vulnerability.";

if(description)
{
  script_id(801433);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)");
  script_cve_id("CVE-2010-2992");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Wireshark 'packet-gsm_a_rr.c' Denial of Service Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2010-08.html");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Jul/1024269.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/docs/relnotes/wireshark-1.2.10.html");

  script_description(desc);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_summary("Check the version of Wireshark");
  script_category(ACT_GATHER_INFO);
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
  exit(0);
}


include("version_func.inc");

## Get the version from KB
wiresharkVer = get_kb_item("Wireshark/Win/Ver");
if(!wiresharkVer){
  exit(0);
}

## Check for Wireshark Version
if(version_in_range(version:wiresharkVer, test_version:"1.2.2", test_version2:"1.2.9")){
  security_warning(0);
}
