###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_ie_mem_crptn_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Vulnerability in Internet Explorer Could Allow Remote Code Execution (960714)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-06
#        - To detect file version 'mshtml.dll' on vista and win 2008
#
# Copyright: SecPod
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
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could result in memory corruption via a specially
  crafted HTML document.
  Impact Level: Application";
tag_affected = "Internet Explorer 5.01 & 6 on MS Windows 2000
  Internet Explorer 6 on MS Windows 2003 and XP
  Internet Explorer 7 on MS Windows 2003 and XP
  Internet Explorer 7 on MS Windows vista
  Internet Explorer 7 on MS Windows 2008 server";
tag_insight = "The flaw is due to a use-after-free error when HTML elements
  are bound to the same data source.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS08-078";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-078.";


if(description)
{
  script_id(900066);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-4844");
  script_bugtraq_id(32721);
  script_name("Vulnerability in Internet Explorer Could Allow Remote Code Execution (960714)");
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
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS08-078");

  script_description(desc);
  script_summary("Check for the vulnerable File Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

ieVer = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer",
                        item:"Version");
if(!ieVer){
  ieVer = registry_get_sz(item:"IE",
          key:"SOFTWARE\Microsoft\Internet Explorer\Version Vector");
}

if(!ieVer){
  exit(0);
}

# MS08-078 Hotfix (960714)
if(hotfix_missing(name:"960714") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  vers = get_file_version(sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5, xp:4) > 0)
    {
      # Check for IE version 5 < 5.0.3872.1000
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3872.999")||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1618"))
      {
        security_hole(0);
        exit(0);
      }
    }

    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for IE version 6 < 6.0.2900.3492
        if(version_in_range(version:vers, test_version:"6.0.2900.0000", test_version2:"6.0.2900.3491")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16787")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20972")||
           version_in_range(version:vers, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18246")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22341")){
          security_hole(0);
        }
      }
      else if("Service Pack 3" >< SP)
      {
        # Check for IE version 6 < 6.0.2900.5726
        if(version_in_range(version:vers, test_version:"6.0.2900.0000", test_version2:"6.0.2900.5725")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16787")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20972")||
           version_in_range(version:vers, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18246")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22341")){
          security_hole(0);
        }
      }
      exit(0);
    }

    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Check for IE version 6 < 6.0.3790.3261
        if(version_in_range(version:vers, test_version:"6.0.3790.0000", test_version2:"6.0.3790.3260")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16787")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20972")){
          security_hole(0);
        }
      }
      else if("Service Pack 2" >< SP)
      {
        # Check for IE version 6 < 6.0.3790.4426
        if(version_in_range(version:vers, test_version:"6.0.3790.0000", test_version2:"6.0.3790.4425")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16787")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20972")||
           version_in_range(version:vers, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18246")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22341")){
          security_hole(0);
        }
      }
      exit(0);
    }
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"System32\mshtml.dll");
  if(dllVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2, win2008:2) > 0)
    {
      ## Check for the Vista and server 2008 without SP
      if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16787")||
         version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.20972")||
         version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18246")||
         version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22341"))
      {
        security_hole(0);
        exit(0);
      }

      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP){
        SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        # Grep for mshtml.dll version 
        if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18182")||
           version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22327"))
        {
           security_hole(0);
           exit(0);
        }
      }
    }
  }
}
