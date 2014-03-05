###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_thegreenbow_ipsec_vpn_client_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# TheGreenBow IPSec VPN Client Local Stack Overflow Vulnerability
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
tag_solution = "Apply patch from below link,
  http://www.thegreenbow.com/download.php?id=1000150

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Successful exploitation allows the attacker to execute arbitrary code on
  the system or compromise a system.
  Impact Level:System/Application";
tag_affected = "TheGreenBow IPSec VPN Client version 4.65.003 and prior.";
tag_insight = "The flaw is due to a boundary error when processing certain sections of
  'tgb' (policy) files. Passing an overly long string to 'OpenScriptAfterUp' will
  trigger the overflow.";
tag_summary = "This host has TheGreenBow IPSec VPN Client installed and is prone to Stack
  Overflow vulnerability.";

if(description)
{
  script_id(902104);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-0392");
  script_name("TheGreenBow IPSec VPN Client Local Stack Overflow Vulnerability");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/38262");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55793");
  script_xref(name : "URL" , value : "http://www.senseofsecurity.com.au/advisories/SOS-10-001");

  script_description(desc);
  script_summary("Check for the version of TheGreenBow IPSec VPN Client");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_thegreenbow_ipsec_vpn_client_detect.nasl");
  script_require_keys("TheGreenBow-IPSec-VPN-Client/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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

# Check for TheGreenBow IPSec VPN Client version <= 4.65.003 (4.6.5.3)
if(version_is_less_equal(version:vpnVer, test_version:"4.6.5.3")){
  security_hole(port:vpnPort, proto:"udp");
}
