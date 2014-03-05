###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-035.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (982381)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-15
#    - To detect required file version on vista, win 2008 and win 7 os
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
tag_impact = "Successful exploitation will let remote attackers to bypass security
  restrictions, gain knowledge of sensitive information or compromise a
  vulnerable system.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 5.x/6.x/7.x/8.x";
tag_insight = "Multiple flaws are due to:
  - An error in the way the browser handles content using specific strings when
    sanitizing HTML via the 'toStaticHTML' API.
  - An uninitialized memory error when processing certain HTML data, which could
    be exploited by attackers to execute arbitrary code via a malicious web page.
  - Caching data and incorrectly allowing the cached content to be rendered as 
    HTML, which could allow attackers to bypass domain restrictions.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-035.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-035.";

if(description)
{
  script_id(902191);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-09 17:19:57 +0200 (Wed, 09 Jun 2010)");
  script_cve_id("CVE-2010-0255", "CVE-2010-1257", "CVE-2010-1259", "CVE-2010-1260",
                "CVE-2010-1261", "CVE-2010-1262");
  script_bugtraq_id(38056, 38547, 40410, 40414, 40416, 40417);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (982381)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/982381");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1392");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-035.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable 'Iepeers.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# This function will return the version of the given file
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

## MS10-035 Hotfix (982381)
if(hotfix_missing(name:"982381") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"Iepeers.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      ## Check for Iepeers.dll version 5.0 < 5.0.3888.1400 or 6.0 < 6.0.2800.1649
      if(version_in_range(version: dllVer, test_version:"5.0.0000.0000", test_version2:"5.0.3888.1399")||
         version_in_range(version: dllVer, test_version:"6.0.0000.0000", test_version2:"6.0.2800.1648")){
         security_hole(0);
      }
      exit(0);
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        ## Check for Iepeers.dll version 6.0 < 6.0.2900.3698
        if(version_in_range(version: dllVer, test_version:"6.0.0000.0000", test_version2:"6.0.2900.3697")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17054")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21255")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18922")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23013")){
           security_hole(0);
        }
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        ## Check for Iepeers.dll version 7 < 6.0.2900.5969, 7 < 7.0.6000.17055,
        ## 8.0 < 8.0.6001.18923
        if(version_in_range(version: dllVer, test_version:"6.0.0000.0000", test_version2:"6.0.2900.5968")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17054")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21255")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18922")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23013")){
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
        ## Check for Iepeers.dll version 6.0 < 6.0.3790.4696 , 7.0 < 7.0.6000.17055
        ## 8.0 < 8.0.6001.18923
        if(version_in_range(version: dllVer, test_version:"6.0.0000.0000", test_version2:"6.0.3790.4695") ||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17054")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21255")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18922")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23013")){
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
  dllVer = get_file_version(sysPath, file_name:"System32\Iepeers.dll");
  if(dllVer)
  {
    # Windows Vista and Windows Server 2008
    if(hotfix_check_sp(winVista:3, win2008:3) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");

      if(!SP) {
        SP = get_kb_item("SMB/Win2008/ServicePack");
      }

      if("Service Pack 1" >< SP)
      {
        # Grep for Iepeers.dll version
        if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18469")||
           version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22684")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18927")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23397")){
           security_hole(0);
        }
        exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        # Grep for Iepeers.dll version
        if(version_in_range(version: dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18254")||
           version_in_range(version: dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22397")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18927")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.23397")){
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
  dllVer = get_file_version(sysPath, file_name:"System32\Ieframe.dll");
  if(!dllVer){
    exit(0);
  }
}

# Windows 7
if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for Ieframe.dll version 
  if(version_in_range(version:dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16587")||
     version_in_range(version:dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.20707")){
     security_hole(0);
  }
}

