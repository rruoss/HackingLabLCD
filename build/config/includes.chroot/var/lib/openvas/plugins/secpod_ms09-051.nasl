###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-051.nasl 15 2013-10-27 12:49:54Z jan $
#
# Vulnerabilities in Windows Media Runtime Could Allow Remote Code Execution (975682)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-25
#   - To detect file version 'wmspdmod.dll' on vista and win 2008
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM privileges and can cause Denial of Service.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 2k Service Pack 2 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2k3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "Multiple flaws are due to
  - Memory corruption error when processing specially crafted ASF files that
    make use of the Window Media Speech codec.
  - Error in Windows Media Runtime due to improper initialization of certain
    functions in compressed audio files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-051.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-051.";

if(description)
{
  script_id(901039);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-14 16:47:08 +0200 (Wed, 14 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0555", "CVE-2009-2525");
  script_bugtraq_id(36614, 36602);
  script_name("Vulnerabilities in Windows Media Runtime Could Allow Remote Code Execution (975682)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2887");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/alerts/2009/Oct/1023005.html");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-051.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable DLL file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

if((hotfix_missing(name:"954155") == 0)||(hotfix_missing(name:"975025") == 0)){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"wmspdmod.dll");
  if(!dllVer){
    exit(0);
  }
}
 
 # Windows 2000
  if(hotfix_check_sp(win2k:5) > 0)
  {
    # Check for wmspdmod.dll version  <  9.0.0.3269 ,10.0.0.4070
    if(version_in_range(version:dllVer, test_version:"9.0",
                                       test_version2:"9.0.0.3268")||
       version_in_range(version:dllVer, test_version:"10.0",
                                       test_version2:"10.0.0.4069")){
      security_hole(0);
    }
  }

  # Windows XP
  else if(hotfix_check_sp(xp:4) > 0)
  {
    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP || "Service Pack 3" >< SP)
    {
      # Windows Media Audio Voice Decoder
      # Grep for wmspdmod.dll < 9.0.0.3269, 9.0.0.4505, 10.0.0.4364,
      # 10.0.0.4070, 10.0.0.3704, 11.0.5721.5262
      if(version_in_range(version:dllVer, test_version:"9.0.0.3",
                                         test_version2:"9.0.0.3268")||
         version_in_range(version:dllVer, test_version:"9.0.0.4",
                                         test_version2:"9.0.0.4504")||
         version_in_range(version:dllVer, test_version:"10.0.0.3",
                                         test_version2:"10.0.0.3703")||
         version_in_range(version:dllVer, test_version:"10.0.0.40",
                                         test_version2:"10.0.0.4069")||
         version_in_range(version:dllVer, test_version:"10.0.0.43",
                                         test_version2:"10.0.0.4364")||
         version_in_range(version:dllVer, test_version:"11.0.0.0",
                                         test_version2:"11.0.5721.5262")){
         security_hole(0);
      }
      exit(0);
    }
    security_hole(0);
  }

  # Windows 2003
  else if(hotfix_check_sp(win2003:3) > 0)
  {
    SP = get_kb_item("SMB/Win2003/ServicePack");
    if(("Service Pack 1" >< SP)||("Service Pack 2" >< SP))
    {
      # Check for wmspdmod.dll  version < 10.0.0.3712 ,10.0.0.4004
      if(version_in_range(version:dllVer, test_version:"10.0.0.3",
                                         test_version2:"10.0.0.3711") ||
         version_in_range(version:dllVer, test_version:"10.0.0.4",
                                         test_version2:"10.0.0.4003")){
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
  dllVer = get_file_version(sysPath, file_name:"System32\wmspdmod.dll");
  if(!dllVer){
    exit(0);
  }
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for wmspdmod.dll version < 11.0.6001.7005
    if(version_is_less(version:dllVer, test_version:"11.0.6001.7005")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for wmspdmod.dll version < 11.0.6002.18034
      if(version_is_less(version:dllVer, test_version:"11.0.6002.18034")){
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
    # Grep for wmspdmod.dll version < 11.0.6001.7005
    if(version_is_less(version:dllVer, test_version:"11.0.6001.7005")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for wmspdmod.dll version < 11.0.6002.18034
    if(version_is_less(version:dllVer, test_version:"11.0.6002.18034")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}

#Audio Compression Manager
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath +
                                                        "\msaud32.acm");
dllVer = GetVer(share:share, file:file);
if(dllVer)
{
  if(version_is_less(version:dllVer, test_version:"8.0.0.4502")){
    security_hole(0);
  }
}
