###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-071.nasl 16 2013-10-27 13:09:52Z jan $
#
# Vulnerabilities in GDI Could Allow Remote Code Execution (956802)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-07
#        - To detect file version 'gdi32.dll' on vista and win 2008
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
tag_impact = "Successful exploitation could allow execution of arbitrary code on the remote
  system and cause heap based buffer overflow via a specially crafted WMF file.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K/XP/2003/Vista/2008 Server";
tag_insight = "The flaw is due to,
  - an overflow error in GDI when processing headers in Windows Metafile (WMF)
    files.
  - an error in the the way the GDI handles file size parameters in WMF files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms08-071.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-071.";


if(description)
{
  script_id(900059);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-2249", "CVE-2008-3465");
  script_bugtraq_id(32634, 32637);
  script_name("Vulnerabilities in GDI Could Allow Remote Code Execution (956802)");
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
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-071.mspx");

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

# Check for Hotfix 956802 (MS08-071).
if(hotfix_missing(name:"956802") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"gdi32.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for gdi32.dll version < 5.0.2195.7205
      if(version_is_less(version:dllVer, test_version:"5.0.2195.7205")){
        security_hole(0);
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for gdi32.dll version < 5.1.2600.3466
        if(version_is_less(version:dllVer, test_version:"5.1.2600.3466")){
          security_hole(0);
        }
      }
      else if("Service Pack 3" >< SP)
      {
        # Check for gdi32.dll version < 5.1.2600.5698
        if(version_is_less(version:dllVer, test_version:"5.1.2600.5698")){
          security_hole(0);
        }
      }
       else security_hole(0);
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Check for gdi32.dll version < 5.2.3790.3233
        if(version_is_less(version:dllVer, test_version:"5.2.3790.3233")){
          security_hole(0);
        }
      }
      else if("Service Pack 2" >< SP)
      {
        # Check for gdi32.dll version < 5.2.3790.4396
        if(version_is_less(version:dllVer, test_version:"5.2.3790.4396")){
          security_hole(0);
        }
      }
      else security_hole(0);
    }
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"System32\gdi32.dll");
  if(dllVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for gdi32.dll version < 6.0.6001.18159
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18159")){
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
        # Grep for gdi32.dll version < 6.0.6001.18159
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18159")){
          security_hole(0);
        }
         exit(0);
      }
    }
  }
}

