###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_library_code_exec_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# MS Windows Insecure Library Loading Remote Code Execution Vulnerabilities (2269637)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or to
  elevate privileges.
  Impact Level: Application.";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";

tag_insight = "The flaws are due to:
  - An error in the loading of dynamic link libraries (DLLs). If an application
    does not securely load DLL files, an attacker may be able to cause the
    application to load an arbitrary library.
  - A specific insecure programming practices that allow so-called
   'binary planting' or 'DLL preloading attacks', which allows the attacker to
    execute arbitrary code in the context of the user running the vulnerable
    application when the user opens a file from an untrusted location.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  htttp://www.microsoft.com/technet/security/advisory/2269637.mspx";
tag_summary = "This host is prone to Remote Code Execution vulnerabilities.";

if(description)
{
  script_id(801399);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-03 15:47:26 +0200 (Fri, 03 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("MS Windows Insecure Library Loading Remote Code Execution Vulnerabilities (2269637)");
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
  script_xref(name : "URL" , value : "http://secunia.com/blog/120/");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/2269637.mspx");
  script_xref(name : "URL" , value : "http://www.network-box.com/aboutus/news/microsoft-advises-insecure-library-loading-vulnerability");

  script_description(desc);
  script_summary("Check for version of vulnurable file 'Ntdll.dll'");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## This function will return the version of the given file
function get_file_version(dllPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:dllPath + "\" + file_name);

  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    return(FALSE);
  }

  return(dllVer);
}

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

## Hotfix check
if(hotfix_missing(name:"2264107") == 0){
  exit(0);
}

## Get System32 path
dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(dllPath)
{
  sysVer = get_file_version(dllPath, file_name:"Ntdll.dll");
  if(sysVer)
  {
    ## Windows XP
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 3" >< SP)
      {
        ## Grep for Ntdll.dll version < 5.1.2600.6007
        if(version_is_less(version:sysVer, test_version:"5.1.2600.6007")){
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
        # Grep for  Ntdll.dll version < 5.2.3790.4737
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4737")){
          security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }
  }
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!dllPath){
  exit(0);
}

sysVer = get_file_version(dllPath, file_name:"system32\Ntdll.dll");
if(!sysVer){
  exit(0);
}

# Windows Vista
if(hotfix_check_sp(winVista:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Ntdll.dll version < 6.0.6001.18499
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18499")){
      security_hole(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Ntdll.dll version < 6.0.6002.18279
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18279")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

# Windows Server 2008
else if(hotfix_check_sp(win2008:2) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Ntdll.dll version < 6.0.6001.18499
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18499")){
      security_hole(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Ntdll.dll version < 6.0.6002.18279
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18279")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

## Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for Ntdll.dll version < 6.1.7600.16625
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16625")){
    security_hole(0);
  }
}
