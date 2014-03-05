###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-096.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Address Book Remote Code Execution Vulnerability (2423089)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code.
  Impact Level: System";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The Address Book (wab.exe) application insecurely loads certain librairies
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a vCard file from a network
  share.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-096.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-096.";

if(description)
{
  script_id(901169);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)");
  script_bugtraq_id(42648);
  script_cve_id("CVE-2010-3147");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Windows Address Book Remote Code Execution Vulnerability (2423089)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41050");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2423089");
  script_xref(name : "URL" , value : "http://www.attackvector.org/new-dll-hijacking-exploits-many/");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-096.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable wab.exe file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

## Check For OS and Service Packs
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## Check for MS10-096 Hotfix
if(hotfix_missing(name:"2423089") == 0){
  exit(0);
}

## Get System Path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
if(!sysPath){
  exit(0);
}

## Get Application Path
appPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wab.exe",
                         item:"Path");
if(!appPath){
  exit(0);
}

appPath = ereg_replace(pattern:"%.*%(.*)", replace:"\1", string:appPath);
wabPath = sysPath + appPath + "\wab.exe";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wabPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:wabPath);

## Get file Version
wabVer = GetVer(file:file, share:share);
if(!wabVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if(("Service Pack 3" >< SP))
  {
    ## Grep for wab.exe version < 6.0.2900.6040
    if(version_is_less(version:wabVer, test_version:"6.0.2900.6040")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Grep for wab.exe version < 6.0.3790.4785
    if(version_is_less(version:wabVer, test_version:"6.0.3790.4785")){
      security_hole(0);
    }
     exit(0);
  }
  security_hole(0);
}

## Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    ## Check for wab.exe version < 6.0.6001.18535
    if(version_is_less(version:wabVer, test_version:"6.0.6001.18535")){
      security_hole(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for wab.exe version < 6.0.6002.18324
    if(version_is_less(version:wabVer, test_version:"6.0.6002.18324")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

## Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  ## Check for wab.exe version < 6.1.7600.16684
  if(version_is_less(version:wabVer, test_version:"6.1.7600.16684")){
    security_hole(0);
  }
}
