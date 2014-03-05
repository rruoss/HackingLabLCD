###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms10-009.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows TCP/IP Could Allow Remote Code Execution (974145)
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code with system privileges. Failed exploit attempts will likely result in
  denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaws are due to Windows TCP/IP stack,
  - not performing the appropriate level of bounds checking on specially crafted
    'ICMPv6' Router Advertisement packets.
  - fails to properly handle malformed Encapsulating Security Payloads (ESP) over
    UDP datagram fragments while running a custom network driver that splits the
    UDP header into multiple MDLs, which could be exploited by remote attackers
    to execute arbitrary code by sending specially crafted IP datagram fragments
    to a vulnerable system.
  - not performing the appropriate level of bounds checking on specially crafted
    ICMPv6 Route Information packets, which could be exploited by remote
    attackers to execute arbitrary code by sending specially crafted ICMPv6
    packets to a vulnerable system.
  - not properly handling TCP packets with a malformed selective acknowledgment
    (SACK) value.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-009.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-009.";

if(description)
{
  script_id(801479);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-11-25 08:29:59 +0100 (Thu, 25 Nov 2010)");
  script_cve_id("CVE-2010-0239", "CVE-2010-0240", "CVE-2010-0241",
                "CVE-2010-0242");
  script_bugtraq_id(38061, 38062, 38063, 38064);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Windows TCP/IP Could Allow Remote Code Execution (974145)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38506/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0342");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-009.mspx");

  script_description(desc);
  script_summary("Check for the version of Tcpip.sys file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win2008:3) <= 0){
  exit(0);
}

## Check Hotfix MS10-009
if(hotfix_missing(name:"974145") == 0){
  exit(0);
}

## Get System Path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\System32\drivers\tcpip.sys");

## Get File Version
sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for tcpip.sys version < 6.0.6001.18377
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18377")){
      security_hole(0);
    }
      exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for tcpip.sys version < 6.0.6002.18160
      if(version_is_less(version:sysVer, test_version:"6.0.6002.18160")){
      security_hole(0);
    }
      exit(0);
  }
  security_hole(0);
}

# Windows Server 2008
else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep tcpip.sys version < 6.0.6001.18377
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18377")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for tcpip.sys version < 6.0.6002.18160
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18160")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}
