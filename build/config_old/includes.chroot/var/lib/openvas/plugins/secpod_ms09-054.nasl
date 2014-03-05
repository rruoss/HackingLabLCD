###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-054.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer Multiple Code Execution Vulnerabilities (974455)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated to KB976749
#  - By Sharath S <sharaths@secpod.com> On 2009-11-04
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-25
#    - To detect file version 'mshtml.dll' on vista and win 2008
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes via
  specially crafted HTML page in the context of the affected system and cause
  memory corruption.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 5.x/6.x/7.x/8.x";
tag_insight = "These issues are caused by memory corruption errors when processing a specially
  crafted data stream header, when handling certain arguments, or when accessing
  certain objects.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS09-054";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-054.";

if(description)
{
  script_id(901041);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-14 18:36:58 +0200 (Wed, 14 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1547", "CVE-2009-2529", "CVE-2009-2530", "CVE-2009-2531");
  script_bugtraq_id(36622, 36621, 36620, 36616);
  script_name("Microsoft Internet Explorer Multiple Code Execution Vulnerabilities (974455)");
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
  script_summary("Check for the vulnerable mshtml.dll file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/974455");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/976749");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2889");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS09-054");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS09-054 Hotfix (974455)
if(hotfix_missing(name:"974455") == 0)
{
  # MS09-054 Hotfix (976749)
  if(hotfix_missing(name:"976749") == 0){
    exit(0);
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  vers = get_file_version(sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for mshtml.dll version < 5.0.3881.1900 or 6.0 < 6.0.2800.1640
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3881.1899") ||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1639"))
      {
        security_hole(0);
        exit(0);
      }
    }
    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.2900.3636 7.0.6000.10000 < 7.0.6000.16939,
        # 7.0.6000.20000 < 7.0.6000.21142, 8.0.6001.10000 < 8.0.6001.18852 and 8.0.6001.20000 < 8.0.6001.22942
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3635")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16938")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21141")||
           version_in_range(version:vers, test_version:"8.0.6000.16000", test_version2:"8.0.6001.18851")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22941")){
           security_hole(0);
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.2900.5890, 7.0.6000.10000 < 7.0.6000.16939,
        # 7.0.6000.20000 < 7.0.6000.21142, 8.0.6001.10000 < 8.0.6001.18852 and 8.0.6001.20000 < 8.0.6001.22942
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.5889")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16938")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21141")||
           version_in_range(version:vers, test_version:"8.0.6000.16000", test_version2:"8.0.6001.18851")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22941")){
           security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }
    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.3790.4605 , 7.0 < 	7.0.6000.16939,
        # 7.0.6000.20000 < 7.0.6000.21142, 8.0.6001.10000 < 8.0.6001.18852 and 8.0.6001.20000 < 8.0.6001.22942
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4604") ||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16938")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21141")||
           version_in_range(version:vers, test_version:"8.0.6000.16000", test_version2:"8.0.6001.18851")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22941")){
           security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }
  }
}

## Get System Path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

dllVer = get_file_version(sysPath, file_name:"System32\mshtml.dll");
if(!dllVer){
  exit(0);
}

# Windows Vista
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for the Vista and server 2008 without SP
  ## Grep for mshtml.dll version
  if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16915")||
     version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21115")||
     version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18827")||
     version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22917"))
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
    if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18318")||
       version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22507")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18827")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22917")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for mshtml.dll version
    if(version_in_range(version: dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18099")||
       version_in_range(version: dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22211")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18827")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22917")){
      security_hole(0);
    }
    exit(0);
  }
}

# Windows 7
if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for  mshtml.dll < 8.0.7600.16419
  if(version_in_range(version: dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16418")){
     security_hole(0);
  }
}
