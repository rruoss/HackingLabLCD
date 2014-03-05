###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-034.nasl 15 2013-10-27 12:49:54Z jan $
#
# Cumulative Security Update for Internet Explorer (972260)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-30
#  - To detect file version 'mshtml.dll' on vista and win 2008
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-05-18
#  - Added exit() to avoid FP check for windows XP SP3
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
tag_impact = "Specially crafted HTML page will let the attacker execute arbitrary
  codes in the context of the affected system and cause memory corruption.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 5.x/6.x/7.x/8.x";
tag_insight = "Multiple errors occur due to the way IE
  - handles memory objects,
  - handles table operations,
  - access a previously deleted object.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS09-034";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-034.";

if(description)
{
  script_id(900906);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-29 15:02:57 +0200 (Wed, 29 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-1917", "CVE-2009-1918", "CVE-2009-1919");
  script_bugtraq_id(35831, 35827);
  script_name("Cumulative Security Update for Internet Explorer (972260)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/972260");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS09-034");

  script_description(desc);
  script_summary("Check for the vulnerable DLL file version");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS09-034 Hotfix (972260)
if(hotfix_missing(name:"972260") == 0){
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
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for mshtml.dll version 5.0 < 5.0.3879.2200 or 6.0 < 6.0.2800.1634
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3879.2199")||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1633"))
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
        # Check for mshtml.dll version 6.0 < 6.0.2900.3603
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3602")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16889")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
           version_in_range(version:vers, test_version:"8.0.6001.16000", test_version2:"8.0.6001.18811")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22901")){
          security_hole(0);
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.2900.5848 or 7.0 < 7.0.6000.16890
        # or 8.0 < 8.0.6001.18806
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.5847")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16889")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
           version_in_range(version:vers, test_version:"8.0.6001.16000", test_version2:"8.0.6001.18811")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22901")){
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
        # Check for mshtml.dll version 6.0 < 6.0.3790.4555 or 7.0 < 7.0.6000.16890
        # or 8.0 < 8.0.6001.18812
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4554")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16889")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
           version_in_range(version:vers, test_version:"8.0.6001.16000", test_version2:"8.0.6001.18811")||
           version_in_range(version:vers, test_version:"8.0.6001.20000", test_version2:"8.0.6001.22901")){
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

# Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for the Vista and server 2008 without SP
  ## Grep for mshtml.dll version
  if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16889")||
     version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21088")||
     version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18812")||
     version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22902"))
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
    if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18293")||
       version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22474")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18812")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22902")){
      security_hole(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for mshtml.dll version
    if(version_in_range(version: dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18070")||
       version_in_range(version: dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22179")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18812")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22902")){
      security_hole(0);
    }
    exit(0);
  }
}
