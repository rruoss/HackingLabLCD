###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-059.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Windows LSASS Denial of Service Vulnerability (975467)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-24
#    - To detect file version 'Msv1_0.dll' on vista, win 2008 and 7
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
tag_impact = "Successful exploitation will allow remote attackers to cause a Denial of
  Service on the victim's system.
  Impact Level: System";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "This issue is caused by an integer underflow error in the Windows NTLM
  implementation in LSASS (Local Security Authority Subsystem Service) when
  processing malformed packets during the authentication process, which could
  allow attackers to cause an affected system to automatically reboot.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-059.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-059.";

if(description)
{
  script_id(900877);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-14 16:47:08 +0200 (Wed, 14 Oct 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2524");
  script_bugtraq_id(36593);
  script_name("Microsoft Windows LSASS Denial of Service Vulnerability (975467)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/975467");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2894");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS09-059.mspx");

  script_description(desc);
  script_summary("Check for the version of Msv1_0.dll file");
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

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

# Check KB968389 is installed, vulnerability exists only if this is installed.
if(hotfix_missing(name:"968389") == 1){
  exit(0);
}

# MS09-059 Hotfix check
if(hotfix_missing(name:"975467") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"Msv1_0.dll");
  if(!dllVer){
    exit(0);
  }
}

# Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Msv1_0.dll < 5.1.2600.3625
    if(version_is_less(version:dllVer, test_version:"5.1.2600.3625")){
      security_hole(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Msv1_0.dll < 5.1.2600.5876
    if(version_is_less(version:dllVer, test_version:"5.1.2600.5876")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}
# Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Msv1_0.dll version < 5.2.3790.4587
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4587")){
      security_hole(0);
    }
     exit(0);
  }
  security_hole(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"System32\Msv1_0.dll");
  if(!dllVer){
    exit(0);
  }
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Msv1_0.dll version < 6.0.6001.18330
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18330")){
      security_hole(0);
    }
      exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Msv1_0.dll version < 6.0.6002.18111
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18111")){
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
    # Grep for Msv1_0.dll version < 6.0.6001.18330
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18330")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Msv1_0.dll version < 6.0.6002.18111
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18111")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for Msv1_0.dll version < 
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16420")){
     security_hole(0);
  }
}

