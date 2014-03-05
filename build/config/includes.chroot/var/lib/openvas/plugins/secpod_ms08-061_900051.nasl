##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-061_900051.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Windows Kernel Elevation of Privilege Vulnerability (954211)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-061.mspx";

tag_impact = "Successfull local exploitation could result in denial of service
  condition due to memory corruption and can execute arbitrary code with
  elevated privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1 and prior.
  Microsoft Windows 2008 Server Service Pack 1 and prior.";
tag_insight = "Multiple flaws are due to,
  - an error within the processing of window properties passed from
    a parent to a child window when a new window is created.
  - an error while processing unspecified user mode input.
  - a double-free error within the handling of system calls from multiple
    threads.";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-061.";


if(description)
{
  script_id(900051);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31651, 31652, 31653);
  script_cve_id("CVE-2008-2250", "CVE-2008-2251", "CVE-2008-2252");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Windows Kernel Elevation of Privilege Vulnerability (954211)");
  script_summary("Check for Hotfix and version of Windows Kernel File");
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
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-061.mspx");
  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

# Check for Hotfix 954211 (MS08-061)
if(hotfix_missing(name:"954211") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"Win32k.sys");
  if(sysVer)
  {
    # Windows 2K
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Grep for Win32k.sys version < 5.0.2195.7194
      if(egrep(pattern:"^5\.0\.2195\.([0-6]?[0-9]?[0-9]?[0-9]|7(0[0-9][0-9]|" +
                   "1[0-8][0-9]|19[0-3]))$", string:sysVer)){
        security_hole(0);
      }
      exit(0);
    }

    # Windows XP
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Grep for Win32k.sys < 5.1.2600.3446
        if(egrep(pattern:"^5\.1\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-3][0-9][0-9]|" +
                     "4([0-3][0-9]|4[0-5])))$", string:sysVer)){
          security_hole(0);
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Grep for Win32k.sys < 5.1.2600.5676
        if(egrep(pattern:"^5\.1\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-5][0-9][0-9]|" +
                     "6([0-6][0-9]|7[0-5])))$", string:sysVer)){
          security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }

    # Windows 2003
    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Win32k.sys version < 5.2.3790.3212
        if(egrep(pattern:"^5\.2\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3([01][0-9][0-9]|" +
                     "2(0[0-9]|1[01])))$", string:sysVer)){
           security_hole(0);
        }
        exit(0);
      }
      else if("Service Pack 2" >< SP)
      {
        # Grep for Win32k.sys version < 5.2.3790.4375
        if(egrep(pattern:"^5\.2\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|" +
                     "3([0-6][0-9]|7[0-4])))$", string:sysVer)){
          security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"System32\Win32k.sys");
  if(sysVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Win32k.sys version < 6.0.6001.18141
        if(version_is_less(version:sysVer, test_version:"6.0.6001.18141")){
          security_hole(0);
        }
         exit(0);
      }
    }

    # Windows Server 2008
    else if(hotfix_check_sp(win2008:2) > 0)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Win32k.sys version < 6.0.6001.18141
        if(version_is_less(version:sysVer, test_version:"6.0.6001.18141")){
          security_hole(0);
        }
         exit(0);
      }
    }
  }
}
