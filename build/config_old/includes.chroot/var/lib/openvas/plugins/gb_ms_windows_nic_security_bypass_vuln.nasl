###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_nic_security_bypass_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Windows IPv4 Default Configuration Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to bypass certain security
  restrictions and hijack all network traffic without any user.
  Impact Level: System.";
tag_affected = "Windows 7 Service Pack 1 and prior
  Windows Vista Service Pack 2 and prior
  Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The default Network Interception Configuration prefers a new IPv6 and DHCPv6
  service over a currently used IPv4 and DHCPv4 service upon receipt of an IPv6
  Router Advertisement (RA), and does not provide an option to ignore an unexpected
  RA, which allows remote attackers to conduct man-in-the-middle attacks.";
tag_solution = "No solution or patch is available as of 08th April, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/technet/security/advisory/979682.mspx";
tag_summary = "The host is installed with Microsoft Windows operating system and is prone to
  security bypass vulnerability.

  This NVT has been replaced by NVT secpod_ms10-015.nasl
  (OID:1.3.6.1.4.1.25623.1.0.900740).";

if(description)
{
  script_id(801914);
  script_version("$Revision: 13 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_cve_id("CVE-2010-0232");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Microsoft Windows IPv4 Default Configuration Security Bypass Vulnerability");
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
  script_xref(name : "URL" , value : "http://resources.infosecinstitute.com/slaac-attack/");
  script_xref(name : "URL" , value : "https://lists.immunityinc.com/pipermail/dailydave/20110404/000122.html");

  script_description(desc);
  script_summary("Check for the Microsoft Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


exit(66); ## This NVT is deprecated as addressed in secpod_ms10-015.nasl.

include("smb_nt.inc");
include("secpod_reg.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

dkey = registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters");
if(!dkey){
  exit(0);
}

# Checking For the workaround
dValue = registry_get_dword(key:dkey, item:"DisabledComponents");
if(dValue != NULL && dValue == 0){
  security_hole(0);
}
