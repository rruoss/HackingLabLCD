###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-047.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Kernel Privilege Elevation Vulnerabilities (981852)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-13
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
tag_impact = "Successful exploitation could allow attackers to run arbitrary code in
  kernel level privileges.
  Impact Level: System";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "Multiple error exists due to,
  - The way kernal deals with specific thread creation attempts.
  - An error in initializing the objects while handling certain exceptions.
  - An error in validating access control lists on kernel objects.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-047.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS10-047.";

if(description)
{
  script_id(902093);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_bugtraq_id(42211, 42213, 42221);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-1888", "CVE-2010-1889", "CVE-2010-1890");
  script_name("Microsoft Windows Kernel Privilege Elevation Vulnerabilities (981852)");
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
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Aug/1024307.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-047.mspx");
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

if(hotfix_check_sp(xp:4, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## MS10-047 Hotfix check
if(hotfix_missing(name:"981852") == 0){
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

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Grep for ntoskrnl.exe < 5.1.2600.5973
    if(version_is_less(version:exeVer, test_version:"5.1.2600.5973")){
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
    # Grep for ntoskrnl.exe version < 6.0.6001.18488
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18488")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for ntoskrnl.exe version < 6.0.6002.18267
      if(version_is_less(version:exeVer, test_version:"6.0.6002.18267")){
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
    # Grep for ntoskrnl.exe version < 6.0.6001.18488
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18488")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for ntoskrnl.exe version < 6.0.6002.18267
    if(version_is_less(version:exeVer, test_version:"6.0.6002.18267")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for ntoskrnl.exe version < 6.1.7600.16617
  if(version_is_less(version:exeVer, test_version:"6.1.7600.16617")){
     security_hole(0);
  }
}

