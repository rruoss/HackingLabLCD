###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_netdecision_tftp_server_dir_trav_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# NetDecision TFTP Server Multiple Directory Traversal Vulnerabilities
#
# Authors:
# Sharath s <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod , http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to disclose sensitive
  information,upload or download files to and from arbitrary locations.
  and compromise a vulnerable system to legitimate users.";

tag_affected = "NetMechanica, NetDecision TFTP Server version 4.2 and prior";
tag_insight = "Due to an input validation error within the TFTP server which in fails
  to sanitize user-supplied input in GET or PUT command via ../ (dot dot)
  sequences.";
tag_solution = "No solution or patch is available as of 29th May, 2009. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://www.netmechanica.com";
tag_summary = "This host is running NetDecision TFTP Server and is prone to
  multiple directory traversal vulnerabilities.";

if(description)
{
  script_id(900358);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1730");
  script_bugtraq_id(35002);
  script_name("NetDecision TFTP Server Multiple Directory Traversal Vulnerabilities");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35131");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50574");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/503605");

  script_description(desc);
  script_summary("Check for the version of NetDecision TFTP Server");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl",
                      "secpod_netdecision_tftp_server_detect.nasl");
  script_require_keys("Services/udp/tftp", "NetDecision/TFTP/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");


netdeciPort = get_kb_item("Services/udp/tftp");
if(!netdeciPort){
  netdeciPort = 69;
}

if(!get_udp_port_state(netdeciPort)){
  exit(0);
}

netdeciVer = get_kb_item("NetDecision/TFTP/Ver");
if(netdeciVer != NULL)
{
  if(version_is_less_equal(version:netdeciVer, test_version:"4.2")){
    security_hole(netdeciPort, proto:"udp");
  }
}
