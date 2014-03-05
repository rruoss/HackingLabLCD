###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-025.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Windows Kernel Usermode Callback Local Privilege Elevation Vulnerability (941693)
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary code
  with elevated privileges and take complete control of an affected system.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1 and prior.
  Microsoft Windows Server 2008 Service Pack 1 and prior.";
tag_insight = "The flaw is due to input validation error in the Windows kernel when
  processing user-supplied data.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-025.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-025.";

if(description)
{
  script_id(801487);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)");
  script_cve_id("CVE-2008-1084");
  script_bugtraq_id(28554);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("Microsoft Windows Kernel Usermode Callback Local Privilege Elevation Vulnerability (941693)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/29720");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/1149/references");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-025.mspx");
  
  script_description(desc);
  script_summary("Check for the version of 'Win32k.sys' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:2, win2008:2) <= 0){
  exit(0);
}

## Hotfix check
if(hotfix_missing(name:"941693") == 0){
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
      # Grep for Win32k.sys version < 5.0.2195.7154
      if(version_is_less(version:sysVer, test_version:"5.0.2195.7154")){
        security_hole(0);
      }
      exit(0);
    }
 
     ## Windows XP
    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        ## Grep for Win32k.sys version < 5.1.2600.3335
        if(version_is_less(version:sysVer, test_version:"5.1.2600.3335")){
           security_hole(0);
        }
        exit(0);
      }
    }
 
    ## Windows 2003
    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Win32k.sys version < 5.2.3790.3106
        if(version_is_less(version:sysVer, test_version:"5.2.3790.3106")){
           security_hole(0);
        }
        exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        ## Grep for Win32k.sys version < 5.2.3790.4256
        if(version_is_less(version:sysVer, test_version:"5.2.3790.4256")){
          security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }
  }
}    

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
        # Grep for Win32k.sys version < 6.0.6001.18027
        if(version_is_less(version:sysVer, test_version:"6.0.6001.18027")){
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
        # Grep for Win32k.sys version < 6.0.6001.18027
        if(version_is_less(version:sysVer, test_version:"6.0.6001.18027")){
          security_hole(0);
        }
         exit(0);
      }
    }
  }
}

