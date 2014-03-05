###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-012.nasl 15 2013-10-27 12:49:54Z jan $
#
# Vulnerabilities in Windows Could Allow Elevation of Privilege (959454)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-02
#       - To detect file version 'Msdtcprx.dll' on vista and win 2008
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  gaining elevated privileges.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1 and prior.
  Microsoft Windows Server 2008 Service Pack 1 and prior.";
tag_insight = "- Microsoft Distributed Transaction Coordinator (MSDTC) transaction facility
    allowing the NetworkService token to be obtained and used when making an
    RPC call.
  - Windows Management Instrumentation (WMI) provider improperly isolating
    processes that run under the NetworkService or LocalService accounts.
  - RPCSS service improperly isolating processes that run under the
    NetworkService or LocalService accounts.
  - Windows placing incorrect access control lists (ACLs) on threads in the
    current ThreadPool.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-012.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-012.";

if(description)
{
  script_id(900094);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-04-15 18:21:29 +0200 (Wed, 15 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-1436", "CVE-2009-0078", "CVE-2009-0079", "CVE-2009-0080");
  script_bugtraq_id(28833, 34442, 34443, 34444);
  script_name("Vulnerabilities in Windows Could Allow Elevation of Privilege (959454)");
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
  script_summary("Check for the vulnerable File Version and Hotfix");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/959454");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-012.mspx");
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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:2, win2008:2) <= 0){
  exit(0);
}

# Check for Hotfix 952004 (MS09-012)
if(hotfix_missing(name:"952004") == 0 || hotfix_missing(name:"956572") == 0 ){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"Msdtcprx.dll");
  if(sysVer)
  {
    # Windows 2K
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Grep for Msdtcprx.dll version < 2000.2.3549.0
      if(version_is_less(version:sysVer, test_version:"2000.2.3549.0")){
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
        # Grep for Msdtcprx.dll < 2001.12.4414.320
        if(version_is_less(version:sysVer, test_version:"2001.12.4414.320")){
          security_hole(0);
        }
         exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Grep for Msdtcprx.dll < 2001.12.4414.706
        if(version_is_less(version:sysVer, test_version:"2001.12.4414.706")){
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
        #  Grep for Msdtcprx.dll version < 2001.12.4720.3180
        if(version_is_less(version:sysVer, test_version:"2001.12.4720.3180")){
          security_hole(0);
        }
         exit(0);
      }
      else if("Service Pack 2" >< SP)
      {
        # Grep for Msdtcprx.dll version < 2001.12.4720.4340
        if(version_is_less(version:sysVer, test_version:"2001.12.4720.4340")){
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
  dllVer = get_file_version(sysPath, file_name:"System32\Msdtcprx.dll");
  if(dllVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Msdtcprx.dll version < 2001.12.6931.18085
        if(version_is_less(version:dllVer, test_version:"2001.12.6931.18085")){
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
        # Grep for Msdtcprx.dll version < 2001.12.6931.18085
        if(version_is_less(version:dllVer, test_version:"2001.12.6931.18085")){
          security_hole(0);
        }
         exit(0);
      }
    }
  }
}

