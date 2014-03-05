###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-014.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Internet Explorer Remote Code Execution Vulnerability (963027)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-02
#  - To detect file version 'mshtml.dll' on vista and win 2008
#  - Updated to take care of without SP for Vista and Windows 2008
#
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes into
  the context of the affected system and can cause denial of service in the
  affected system.
  Impact Level: System";
tag_affected = "Microsoft Internet Explorer version 5.x/6.x/7.x";
tag_insight = "Flaws are due to
  - Blended threat issue which allows executables to be downloaded in user's
    computer without prompting.
  - Vulnerability in NT LAN Manager which allows the attacker to replay NTLM
    credentials.
  - Arbitrary code execution in Internet Explorer at run time of Internet
    Explorer Browser.
  - Internet Explorer Uninitialized Memory Variant which lets the attacker
    cause remote code execution.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS09-014";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-014.";

if(description)
{
  script_id(900328);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-15 18:21:29 +0200 (Wed, 15 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-2540", "CVE-2009-0550", "CVE-2009-0551", "CVE-2009-0552",
                "CVE-2009-0553", "CVE-2009-0554");
  script_bugtraq_id(29445, 34439, 34438, 34423, 34424, 34426);
  script_name("Microsoft Internet Explorer Remote Code Execution Vulnerability (963027)");
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
  script_summary("Check for the vulnerable file version");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/963027");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS09-014");
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

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS08-073 Hotfix (958215)
if(hotfix_missing(name:"963027") == 0){
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
      # Check for mshtml.dll version 5 < 5.0.3874.1900 or 6 < 6.0.2800.1625
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3874.1899")||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1624")){
        security_hole(0);
      }
      exit(0);
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6 < 6.0.2900.3527 or 7.0 < 7.0.6000.16825
        if(version_in_range(version:vers, test_version:"6.0",test_version2:"6.0.2900.3526")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16824")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21014")){
          security_hole(0);
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Check for mshtml.dll version 6 < 6.0.2900.5764 or 7.0 < 7.0.6000.16825
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.5763")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16824")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21014")){
          security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
      exit(0); 
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Check for mshtml.dll version 6 < 6.0.3790.3304 or 7.0 < 7.0.6000.16825
        if(version_in_range(version:vers, test_version:"6.0",test_version2:"6.0.3790.3303")||
           version_in_range(version:vers, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16824")||
           version_in_range(version:vers, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21014")){
           security_hole(0);
        }
        exit(0);
      }
      else if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6 < 6.0.3790.4470 or 7.0 < 7.0.6000.16825
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4469") ||
           version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16824")){
           security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
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
      if(version_in_range(version:dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16829") ||
         version_in_range(version:dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21022"))
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
        # Grep for mshtml.dll version < 7.0.6001.18226, 7.0.6001.22389
        if(version_in_range(version:dllVer, test_version:"7.0.6001.18000", test_version2:"7.0.6001.18225") ||
           version_in_range(version:dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22388")){
          security_hole(0);
        }
        exit(0);
      }
    }
  }
}
