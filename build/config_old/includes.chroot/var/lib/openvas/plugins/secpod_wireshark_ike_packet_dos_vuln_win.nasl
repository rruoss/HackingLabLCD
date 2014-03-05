###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wireshark_ike_packet_dos_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Wireshark IKE Packet Denial of Service Vulnerability (Win)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation allows attackers to send a specially crafted IKE
  packet to cause the IKEv1 dissector to enter an infinite loop, which leads
  to denial of service.
  Impact Level: Application.";
tag_affected = "Wireshark version 1.6.0 to 1.6.1
  Wireshark version 1.4.0 to 1.4.8 on Windows";
tag_insight = "The flaw is due to an error in 'IKEv1' protocol dissector and the
  function 'proto_tree_add_item()', when add more than 1000000 items to a
  proto_tree, that will cause a denial of service.";
tag_solution = "Upgrade to the Wireshark version 1.4.9, 1.6.2 or later,
  For updates refer to http://www.wireshark.org/download.html";
tag_summary = "This host is installed with Wireshark and is prone to denial of
  service vulnerability.";

if(description)
{
  script_id(902722);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)");
  script_cve_id("CVE-2011-3266");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Wireshark IKE Packet Denial of Service Vulnerability (Win)");
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
  script_copyright("Copyright (c) 2011 SecPod");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_family("Denial of Service");
  script_require_keys("Wireshark/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1025875");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/519049/100/0/threaded");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
wireVer = "";

wireVer = get_kb_item("Wireshark/Win/Ver");
if(!wireVer){
  exit(0);
}

if(version_in_range(version:wireVer, test_version:"1.6.0", test_version2:"1.6.1") ||
   version_in_range(version:wireVer, test_version:"1.4.0", test_version2:"1.4.8")){
  security_warning(0);
}
