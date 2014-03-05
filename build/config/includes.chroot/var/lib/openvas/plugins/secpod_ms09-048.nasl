###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-048.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Windows TCP/IP Remote Code Execution Vulnerability (967723)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-26
#      - To detect file version 'Tcpip.sys' on vista and win 2008
#
#  Copyright:
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code, and it
  may result in Denial of Service condition in an affected system.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 2k  Service Pack 4 and prior
  Microsoft Windows 2k3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "An error in the TCP/IP processing can be exploited to cause connections to
  hang indefinitely in a FIN-WAIT-1 or FIN-WAIT-2 state, and system to stop
  responding to new requests by flooding it using specially crafted packets
  with a TCP receive window size set to a very small value or zero.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-048.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-048.";

if(description)
{
  script_id(900838);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-10 15:23:12 +0200 (Thu, 10 Sep 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-4609", "CVE-2009-1925", "CVE-2009-1926");
  script_bugtraq_id(31545, 36269);
  script_name("Microsoft Windows TCP/IP Remote Code Execution Vulnerability (967723)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36602/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36597/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/967723");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2567");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-048.mspx");

  script_description(desc);
  script_summary("Check for the version of Tcpip.sys file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  security_hole(0);
  exit(0);
}

## This function will return the version of the given file
function get_file_version(sysPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:sysPath + "\" + file_name);

  sysVer = GetVer(file:file, share:share);
  if(!sysVer){
    return(FALSE);
  }

  return(sysVer);
}

if(hotfix_check_sp(win2003:3, win2008:3, winVista:3) <= 0){
  exit(0);
}

# MS09-048 Hotfix check
if(hotfix_missing(name:"967723") == 0){
    exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"drivers\Tcpip.sys");
  if(!sysVer){
    exit(0);
  }
}

# Windows 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Tcpip.sys version < 5.2.3790.4573
     if(version_is_less(version:sysVer, test_version:"5.2.3790.4573")){
        security_hole(0);
     }
      exit(0);
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"System32\drivers\tcpip.sys");
  if(!sysVer){
    exit(0);
  }
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for tcpip.sys version < 6.0.6001.18311
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18311")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for tcpip.sys version < 6.0.6002.18091
      if(version_is_less(version:sysVer, test_version:"6.0.6002.18091")){
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
    # Grep for tcpip.sys version < 6.0.6001.18311
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18311")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for tcpip.sys version < 6.0.6002.18091
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18091")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}

