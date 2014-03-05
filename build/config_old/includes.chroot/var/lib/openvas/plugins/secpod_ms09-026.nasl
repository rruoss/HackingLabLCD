###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-026.nasl 15 2013-10-27 12:49:54Z jan $
#
# Vulnerability in RPC Could Allow Elevation of Privilege (970238)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-01
#       - To detect file version 'Rpcrt4.dll' on vista and win 2008
#
# Copyright (c) 2009 SecPod, http://www.secpod.org
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
tag_impact = "Successful exploitation could allow remote or local attackers to execute
  arbitrary code by sending specially crafted RPC message to a vulnerable
  third-party RPC application
  Impact Level: System";
tag_affected = "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaws occurs because the Remote Procedure Call (RPC) Marshalling Engine
  does not updating its internal state in an appropriate manner.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-026.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-026.";

if(description)
{
  script_id(900668);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-10 16:35:14 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0568");
  script_name("Vulnerability in RPC Could Allow Elevation of Privilege (970238)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1545");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-026.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable file version");
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

# Check Hotfix Missing 970238 (MS09-026)
if(hotfix_missing(name:"970238") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"Rpcrt4.dll");
  if(!sysVer){
      exit(0);
  }
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Rpcrt4.dll  version < 5.0.2195.7281
    if(version_is_less(version:sysVer, test_version:"5.0.2195.7281")){
      security_hole(0);
  }
   exit(0);
}

# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll < 5.1.2600.3555
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3555")){
      security_hole(0);
    }
     exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Rpcrt4.dll < 5.1.2600.5795
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5795")){
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
  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll version < 5.2.3790.4502
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4502")){
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
  dllVer = get_file_version(sysPath, file_name:"System32\Rpcrt4.dll");
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
    # Grep for Rpcrt4.dll version < 6.0.6001.18247
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
        security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll version < 6.0.6002.18024
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
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
    # Grep for Rpcrt4.dll version < 6.0.6001.18247
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll version < 6.0.6002.18024
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}
