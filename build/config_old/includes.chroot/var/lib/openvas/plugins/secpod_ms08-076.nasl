###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-076.nasl 16 2013-10-27 13:09:52Z jan $
#
# Vulnerabilities in Windows Media Components Could Allow Remote Code Execution (959807)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-07
#       - To detect required file version on vista and win 2008
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
tag_impact = "Successful exploitation could allow attackers to disclose NTLM credentials
  to gain access with the privileges of a target user via replay attacks.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K/XP/2003";
tag_insight = "The flaws are due to
  - an error within the Service Principal Name (SPN) implementation when
    handling NTLM credentials.
  - an error when handling ISATAP URLs.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms08-076.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-076.";


if(description)
{
  script_id(900060);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-12-10 17:58:14 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-3009", "CVE-2008-3010");
  script_bugtraq_id(32653, 32654);
  script_name("Vulnerabilities in Windows Media Components Could Allow Remote Code Execution (959807)");
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
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-076.mspx");

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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

function get_version(dllFile)
{
  dllPath = registry_get_sz(item:"Install Path",
                          key:"SOFTWARE\Microsoft\COM3\Setup");
  if(!dllPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:dllPath + dllFile);

  dllVer = GetVer(file:file, share:share);
  return dllVer;
}


# Windows Media Player 6.4 on 2K/XP/2003
activeKey = "SOFTWARE\Microsoft\Active setup\Installed Components\";
playerVer = registry_get_sz(item:"Version",
            key:"SOFTWARE\Microsoft\Active setup\Installed Components" +
                "\{22d6f312-b0f6-11d0-94ab-0080c74c7e95}");
if(playerVer)
{
  # Check for Hotfix 954600 (MS08-076).
  if(hotfix_missing(name:"954600") == 1)
  {
    dllVer = get_version(dllFile:"\Strmdll.dll");
    if(dllVer != NULL)
    {
      if(version_is_less(version:dllVer, test_version:"4.1.0.3937"))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}

# Windows Media Format Runtime 7.1, 9.0, 9.5 and 11 on 2K/XP/2003
dllVer = get_version(dllFile:"\Wmvcore.dll");
if(dllVer)
{
  # Check for Hotfix 952069 (MS08-076).
  if(hotfix_missing(name:"952069") == 1)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for version < 5.0.2195.7151 (7.1 and 9.0)
      if(version_is_less(version:dllVer, test_version:"9.0.0.3268")){
        security_hole(0);
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"9.0",
                            test_version2:"9.0.0.3267")){
          security_hole(0);
        }
        else if(version_in_range(version:dllVer, test_version:"10.0",
                                 test_version2:"10.0.0.3702")){
          security_hole(0);
        }
        else if(version_in_range(version:dllVer, test_version:"11.0",
                                 test_version2:"11.0.5721.5250")){
          security_hole(0);
        }
      }
      else if("Service Pack 3" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"9.0",
                            test_version2:"9.0.0.4503")){
          security_hole(0);
        }
        else if(version_in_range(version:dllVer, test_version:"10.0",
                                 test_version2:"10.0.0.3702")){
          security_hole(0);
        }
        else if(version_in_range(version:dllVer, test_version:"11.0",
                                 test_version2:"11.0.5721.5250")){
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
        if(version_in_range(version:dllVer, test_version:"10.0",
                            test_version2:"10.0.0.3710")){
          security_hole(0);
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"10.0",
                            test_version2:"10.0.0.4000")){
          security_hole(0);
        }
      }
      else security_hole(0);
    }
  }
}
    
## Get system path for windows vista and 2008 server 
dllPath = registry_get_sz(item:"PathName",
                          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
if(!dllPath){
   exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\system32\Wmvcore.dll");

dllVer = GetVer(file:file, share:share);
if(dllVer)
{
  # Check for Hotfix 952069 (MS08-076).
  if(hotfix_missing(name:"952069") == 1)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Wmvcore.dll version < 11.0.6001.7001
        if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.6001.7000")){
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
        # Grep for Wmvcore.dll version < 11.0.6001.7001
        if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.6001.7000")){
          security_hole(0);
        }
        exit(0);
      }
    }
  }
}

# Windows Media Services 4.1 and 9.0 on 2K/2003
# Check for Hotfix 952068 (MS08-076).
if(hotfix_missing(name:"952068") == 1)
{
  if(hotfix_check_sp(win2k:5) > 0)
  {
    dllVer = get_version(dllFile:"\windows media\server\Nsum.exe");
    if(dllVer != NULL)
    {
      if(version_is_less(version:dllVer, test_version:"4.1.0.3936")){
        security_hole(0);
      }
    }
  }
  else if(hotfix_check_sp(win2003:3) > 0)
  {
    dllVer = get_version(dllFile:"\windows media\server\Wmsserver.dll");
    if(dllVer != NULL)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"9.1.1.3845")){
          security_hole(0);
        }
      }
      else if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:dllVer, test_version:"9.1.1.5000")){
          security_hole(0);
        }
      }
      else security_hole(0);
    }
  }

  ## Get system path for windows 2008 server 
  dllPath = registry_get_sz(item:"PathName",
                          key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
  if(!dllPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\system32\windows media\server\Wmsserver.dll");

  dllVer = GetVer(file:file, share:share);
  if(dllVer)
  {
    # Windows Server 2008
    if(hotfix_check_sp(win2008:2) > 0)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Wmsserver.dll version < 9.5.6001.18161
        if(version_is_less(version:dllVer, test_version:"9.5.6001.18161")){
            security_hole(0);
        }
           exit(0);
      }
    }
  }
}

