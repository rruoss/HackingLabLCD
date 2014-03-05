###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-048.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Kernel Mode Drivers Privilege Elevation Vulnerabilities (2160329)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-09-12
#     - To detect file version 'win32k.sys' on vista, win 2008 and win 7
#
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  with kernel privileges.
  Impact Level: System";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaws exists in the kernel-mode device driver due to:
  - Improper validation of an argument passed to a system call.
  - An error in handling certain exceptions.
  - Improper allocation of memory when making a copy from user mode.
  - Improper validation of input passed from user mode.
  - An error in validating all parameters when creating a new window.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-048.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-048.";

if(description)
{
  script_id(902094);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_cve_id("CVE-2010-1887", "CVE-2010-1894", "CVE-2010-1895",
                "CVE-2010-1896", "CVE-2010-1897");
  script_bugtraq_id(42250, 39630, 42245, 42210, 42206);
  script_tag(name:"cvss_base", value:"6.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Microsoft Windows Kernel Mode Drivers Privilege Elevation Vulnerabilities (2160329)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40878");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-048.mspx");

  script_description(desc);
  script_summary("Check for version of vulnurable file 'Win32k.sys'");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

## MS10-048 Hotfix check
if(hotfix_missing(name:"2160329") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"Win32k.sys");
  if(!sysVer){
    exit(0);
  }
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
     ## Grep for Win32k.sys version < 5.1.2600.6003
     if(version_is_less(version:sysVer, test_version:"5.1.2600.6003")){
       security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for  Win32k.sys version < 5.2.3790.4730
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4730")){
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
  sysVer = get_file_version(sysPath, file_name:"System32\Win32k.sys");
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
    # Grep for Win32k.sys version < 6.0.6001.18496
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18496")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Win32k.sys version < 6.0.6002.18275
      if(version_is_less(version:sysVer, test_version:"6.0.6002.18275")){
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
    # Grep for win32k.sys version < 6.0.6001.18496
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18496")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for win32k.sys version < 6.0.6002.18275
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18275")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for win32k.sys version < 6.1.7600.16617
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16617")){
     security_hole(0);
  }
}
