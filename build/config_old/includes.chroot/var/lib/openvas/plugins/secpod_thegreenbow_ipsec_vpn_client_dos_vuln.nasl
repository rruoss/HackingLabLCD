###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_thegreenbow_ipsec_vpn_client_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# TheGreenBow IPSec VPN Client Denial Of Service Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
tag_impact = "Attackers can exploit this issue via crafted requests to x80000034 IOCTL
  probably involving an input or output buffer size of 0 to cause  denial
  of service.
  Impact Level: Application";
tag_affected = "TheGreenBow IPSec VPN Client version 4.61.003 and prior on Windows.";
tag_insight = "The flaw is due to a NULL-pointer dereference error in 'tgbvpn.sys' driver
  when processing x80000034 IOCTLs.";
tag_solution = "No solution or patch is available as of 26th August, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.thegreenbow.com/vpn.html";
tag_summary = "This host has TheGreenBow IPSec VPN Client installed and is prone to Denial
  of Service vulnerability.";

if(description)
{
  script_id(900922);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-2918");
  script_name("TheGreenBow IPSec VPN Client Denial Of Service Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36332/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2294");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/505816/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of TheGreenBow IPSec VPN Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_thegreenbow_ipsec_vpn_client_detect.nasl");
  script_require_keys("TheGreenBow-IPSec-VPN-Client/Ver");
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

vpnPort = 500;
if(!get_udp_port_state(vpnPort)){
  exit(0);
}

vpnVer = get_kb_item("TheGreenBow-IPSec-VPN-Client/Ver");
if(!vpnVer){
  exit(0);
}

# Check for TheGreenBow IPSec VPN Client version <= 4.61.033 (4.6.1.3)
if(version_is_less_equal(version:vpnVer, test_version:"4.6.1.3")){
  security_warning(port:vpnPort, proto:"udp");
}
