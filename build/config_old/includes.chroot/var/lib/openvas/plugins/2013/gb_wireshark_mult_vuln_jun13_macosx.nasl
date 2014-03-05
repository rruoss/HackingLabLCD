###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_mult_vuln_jun13_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Wireshark Multiple Vulnerabilities - June 13 (Mac OS X)
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
tag_impact = "Successful exploitation will allow remote attackers to cause application
  crash, consume memory or heap-based buffer overflow.
  Impact Level: Application";

tag_affected = "Wireshark 1.8.x before 1.8.8 on Mac OS X";
tag_insight = "Multiple flaws due to erros in,
  - 'epan/dissectors/packet-gmr1_bcch.c' in GMR-1 BCCH dissector
  - dissect_iphc_crtp_fh() function in 'epan/dissectors/packet-ppp.c' in PPP
    dissector
  - Array index error in NBAP dissector
  - 'epan/dissectors/packet-rdp.c' in the RDP dissector
  - dissect_schedule_message() function in 'epan/dissectors/packet-gsm_cbch.c'
    in GSM CBCH dissector
  - dissect_r3_upstreamcommand_queryconfig() function in
    'epan/dissectors/packet-assa_r3.c' in Assa Abloy R3 dissector
  - vwr_read() function in 'wiretap/vwr.c' in Ixia IxVeriWave file parser";
tag_solution = "Upgrade to the Wireshark version 1.8.8 or later,
  For updates refer to http://www.wireshark.org/download";
tag_summary = "This host is installed with Wireshark and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803655);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4082", "CVE-2013-4080", "CVE-2013-4079", "CVE-2013-4078",
                "CVE-2013-4077", "CVE-2013-4076", "CVE-2013-4075");
  script_bugtraq_id(60506, 60503, 60498, 60495, 60502, 60499, 60501);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-28 13:52:52 +0530 (Tue, 28 May 2013)");
  script_name("Wireshark Multiple Vulnerabilities - June 13 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028648");
  script_xref(name : "URL" , value : "http://www.wireshark.org/docs/relnotes/wireshark-1.8.8.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/docs/relnotes/wireshark-1.6.16.html");
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
if(sharkVer && sharkVer=~ "^(1.8)")
{
  ## Check for vulnerable Wireshark versions
  if(version_in_range(version:sharkVer, test_version:"1.8.0", test_version2:"1.8.7"))
  {
    security_warning(0);
    exit(0);
  }
}
