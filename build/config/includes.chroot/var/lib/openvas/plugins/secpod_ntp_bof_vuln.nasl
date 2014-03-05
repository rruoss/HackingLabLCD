###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ntp_bof_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# NTP Stack Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation will allow attackers to execute arbitrary
  code or to cause the application to crash.
  Impact Level: Application.";
tag_affected = "NTP versions prior to 4.2.4p7-RC2 on Linux.";
tag_insight = "The flaw is due to a boundary error within the cookedprint()
  function in ntpq/ntpq.c while processing malicious response from
  a specially crafted remote time server.";
tag_solution = "Upgrade to NTP version 4.2.4p7-RC2
  http://www.ntp.org/downloads.html";
tag_summary = "This host has NTP installed and is prone to stack buffer overflow
  vulnerabilities.";

if(description)
{
  script_id(900623);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-0159");
  script_bugtraq_id(34481);
  script_name("NTP Stack Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34608");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49838");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/0999");

  script_description(desc);
  script_summary("Check for the version of NTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_require_keys("NTP/Linux/Ver");
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

ntpPort = 123;
if(!get_udp_port_state(ntpPort)){
  exit(0);
}

fullVer = get_kb_item("NTP/Linux/FullVer");
if(fullVer && fullVer == "ntpd 4.2.4p4@1.1520-o Sun Nov 22 17:34:54 UTC 2009 (1)") {
  exit(0); # debian backport
}  

ntpVer = get_kb_item("NTP/Linux/Ver");
if(!ntpVer){
  exit(0);
}

if(version_is_less(version:ntpVer, test_version:"4.2.4.p7.RC2")){
  security_hole(port:ntpPort, proto:"udp");
}
