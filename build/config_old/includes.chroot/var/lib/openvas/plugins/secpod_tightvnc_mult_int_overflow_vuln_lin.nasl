###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tightvnc_mult_int_overflow_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# TightVNC ClientConnection Multiple Integer Overflow Vulnerabilities (Linux)
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and may cause remote code execution to compromise
  the affected remote system.

  Impact level: Application/System";

tag_affected = "TightVNC version 1.3.9 and prior on Linux.";
tag_insight = "Multiple Integer Overflow due to signedness errors within the functions
  ClientConnection::CheckBufferSize and ClientConnection::CheckFileZipBufferSize
  in ClientConnection.cpp file fails to validate user input.";
tag_solution = "Upgrade to the latest version 1.3.10
  http://www.tightvnc.com/download.html";
tag_summary = "This host is running TightVNC and is prone to Multiple Integer
  Overflow Vulnerability.";

if(description)
{
  script_id(900475);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_bugtraq_id(33568);
  script_cve_id("CVE-2009-0388");
  script_name("TightVNC ClientConnection Multiple Integer Overflow Vulnerabilities (Linux)");
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
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/7990");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/8024");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/vnc-integer-overflows");

  script_description(desc);
  script_summary("Check for the version of TightVNC");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_tightvnc_detect_lin.nasl", "find_service1.nasl");
  script_require_ports("Services/vnc", 5801, 5901);
  script_require_keys("TightVNC/Linux/Ver");
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

tvncPort = get_kb_item("Services/vnc");
if(!tvncPort){
  exit(0);
}

if(get_port_state(tvncPort))
{
  tvncVer = get_kb_item("TightVNC/Linux/Ver");
  if(!tvncVer){
    exit(0);
  }

  # Grep for TightVNC version 1.3.9 and prior on Linux
  if(version_is_less_equal(version:tvncVer, test_version:"1.3.9")){
    security_hole(tvncPort);
  }
}
