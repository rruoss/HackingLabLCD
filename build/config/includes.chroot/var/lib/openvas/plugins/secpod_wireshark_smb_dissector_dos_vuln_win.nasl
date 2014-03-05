###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_smb_dissector_dos_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Wireshark SMB dissector Denial of Service Vulnerability (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow the attackers to crash an affected
  application.
  Impact Level: Application";
tag_affected = "Wireshark version 0.99.6 through 1.0.13, and 1.2.0 through 1.2.8";
tag_insight = "The flaw is caused by a NULL pointer dereference error in the 'SMB' dissector,
  which could be exploited to crash an affected application via unknown vectors.";
tag_solution = "Upgrade to Wireshark version 1.0.14 or 1.2.9:
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to Denial of
  Service vulnerability.";

if(description)
{
  script_id(902196);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-22 13:34:32 +0200 (Tue, 22 Jun 2010)");
  script_cve_id("CVE-2010-2283");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Wireshark SMB dissector Denial of Service Vulnerability (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40112");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1418");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2010-05.html");
  script_xref(name : "URL" , value : "http://www.wireshark.org/security/wnpa-sec-2010-06.html");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/06/11/1");

  script_description(desc);
  script_summary("Check for the version of Wireshark");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

sharkVer = get_kb_item("Wireshark/Win/Ver");
if(!sharkVer){
  exit(0);
}

# Check for Wireshark version
if(version_in_range(version:sharkVer, test_version:"1.2.0", test_version2:"1.2.8") ||
   version_in_range(version:sharkVer, test_version:"0.99.6", test_version2:"1.0.13")){
  security_warning(0);
}
