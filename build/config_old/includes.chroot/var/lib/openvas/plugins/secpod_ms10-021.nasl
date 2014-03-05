###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-021.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Kernel Could Allow Elevation of Privilege (979683)
#
# Authors:
# Veerendra G <veerendragg@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-18
#      - To detect file version 'Ntoskrnl.exe' on vista, win 2008 and win 7 
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
tag_impact = "Successful exploitation could allow local users to cause a Denial of Service
  or gain escalated privileges.
  Impact Level: System";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows 2K  Service Pack 4 and prior.
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "Multiple error exists in the Windows kernel due to,
  - the way that the kernel handles certain exceptions
  - improper validation of specially crafted image files
  - the manner in which the kernel processes the values of symbolic links
  - insufficient validation of registry keys passed to a Windows kernel system
    call
  - the manner in which memory is allocated when extracting a symbolic link
    from a registry key
  - the way that the kernel resolves the real path for a registry key from its
    virtual path
  - not properly restricting symbolic link creation between untrusted and
    trusted registry hives";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-021.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS10-021.";

if(description)
{
  script_id(900236);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_bugtraq_id(39297, 39309, 39323, 39324, 39318, 39319, 39320, 39322);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0234", "CVE-2010-0235", "CVE-2010-0236", "CVE-2010-0237",
                "CVE-2010-0238", "CVE-2010-0481", "CVE-2010-0482", "CVE-2010-0810");
  script_name("Microsoft Windows Kernel Could Allow Elevation of Privilege (979683)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39374");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39373");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-021.mspx");

  script_description(desc);
  script_summary("Check for the version of ntoskrnl.exe file");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## MS10-021 Hotfix check
if(hotfix_missing(name:"979683") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  exeVer = get_file_version(sysPath, file_name:"ntoskrnl.exe");
  if(!exeVer){
    exit(0);
  }
}

## Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  ## Grep for ntoskrnl.exe version < 5.0.2195.7376
  if(version_is_less(version:exeVer, test_version:"5.0.2195.7376")){
    security_hole(0);
  }
}

## Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Grep for ntoskrnl.exe < 5.1.2600.3670
    if(version_is_less(version:exeVer, test_version:"5.1.2600.3670")){
      security_hole(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    ## Grep for ntoskrnl.exe < 5.1.2600.5938
    if(version_is_less(version:exeVer, test_version:"5.1.2600.5938")){
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
    ## Grep for ntoskrnl.exe version < 5.2.3790.4666
    if(version_is_less(version:exeVer, test_version:"5.2.3790.4666")){
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
  exeVer = get_file_version(sysPath, file_name:"System32\ntoskrnl.exe");
  if(!exeVer){
    exit(0);
  }
}
# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for ntoskrnl.exe version < 6.0.6001.18427
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18427")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for ntoskrnl.exe version < 6.0.6002.18209
      if(version_is_less(version:exeVer, test_version:"6.0.6002.18209")){
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
    # Grep for ntoskrnl.exe version < 6.0.6001.18427
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18427")){
       security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for ntoskrnl.exe version < 6.0.6002.18209
    if(version_is_less(version:exeVer, test_version:"6.0.6002.18209")){
       security_hole(0);
    }
     exit(0);
  }
 security_hole(0);
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for ntoskrnl.exe version < 6.1.7600.16539
  if(version_is_less(version:exeVer, test_version:"6.1.7600.16539")){
     security_hole(0);
  }
}

