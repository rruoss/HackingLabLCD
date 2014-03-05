###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-062.nasl 14 2013-10-27 12:33:37Z jan $
#
# MPEG-4 Codec Remote Code Execution Vulnerability (975558)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
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
tag_affected = "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.

  NOTE: This vulnerability does not affect supported editions of Windows
  Server 2008, when installed using the Server Core installation option.";

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code
  with elevated privileges on vulnerable systems.
  Impact Level: System";
tag_insight = "The flaws exists in MPEG-4 codec included with Windows Media codecs, which
  does not properly handle specially crafted media files that use MPEG-4 video
  encoding.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-062.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-062.";

if(description)
{
  script_id(900250);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)");
  script_bugtraq_id(43039);
  script_cve_id("CVE-2010-0818");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("MPEG-4 Codec Remote Code Execution Vulnerability (975558)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41395");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/975558");

  script_description(desc);
  script_summary("Check for version of vulnurable file MPEG-4 Codec files");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## This function will return the version of the given file
function get_file_version(dllPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file_path =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:dllPath + "\" + file_name);

  dllVer = GetVer(file:file_path, share:share);
  if(!dllVer){
    return(FALSE);
  }

  return(dllVer);
}

## Basic Windows Version and Service Pack check
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

## MS10-062 Hotfix check
if(hotfix_missing(name:"975558") == 0){
  exit(0);
}

## For Windows XP and Windows 2003
if(hotfix_check_sp(xp:4) > 0 || hotfix_check_sp(win2003:3) > 0)
{
  ## Vulnerable, If Windows XP is less less then Service Pack 3
  xpSP = get_kb_item("SMB/WinXP/ServicePack");
  if(xpSP && "Service Pack 3" >!< xpSP){
    security_hole(0);
    exit(0);
  }

  ## Set the wmp11Installed to TRUE, if Windows Media player 11 is installed
  wmp11Installed = FALSE;
  wkey = "SOFTWARE\Microsoft\Active setup\Installed Components\";
  wmpVer = registry_get_sz(key:wkey+ "{6BF52A52-394A-11d3-B153-00C04F79FAA6}",
                           item:"Version");
  if(wmpVer =~ "^(11,|11\.)"){
    wmp11Installed = TRUE;
  }

  ## Get System32 path
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                            item:"Install Path");
  if(!sysPath){
    exit(0);
  }

  ## First 2 files affect both Windows XP and 2003
  ## also file versions are same
  affectedFiles = ["mpg4ds32.ax", "mp4sds32.ax", "mp4sdecd.dll"];

  foreach file (affectedFiles)
  {
    ## Ignore as mp4sdecd.dll file does not affect windows 2003
    if(file == "mp4sdecd.dll" && (hotfix_check_sp(win2003:3) > 0)){
      continue;
    }
    ## Check Windows 11 is installed, if not continue
    else if(file == "mp4sdecd.dll" && !wmp11Installed){
      continue;
    }

    ## Get File Version
    dllVer = get_file_version(dllPath:sysPath, file_name:file);
    if(!dllVer){
      continue;
    }

    if(file == "mpg4ds32.ax"){
      checkVer = "8.0.0.4504";
    }
    else if (file == "mp4sds32.ax"){
      checkVer = "8.0.0.406";
    }
    else if (file == "mp4sdecd.dll"){
      checkVer = "11.0.5721.5274";
    }

    ## Check version is less than "checkVer" variable
    if(version_is_less(version:dllVer, test_version:checkVer)){
      security_hole(0);
      exit(0);
    }
  }
  exit(0);
}


## For Windows Vista and Windows 2008
if(hotfix_check_sp(winVista:2) > 0 || hotfix_check_sp(win2008:2) > 0)
{
  ## Set Service Pack to "SP" variable
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if(!SP){
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  ## Set File Version to "checkVer" variable
  if("Service Pack 1" >< SP)
  {
    ## Mp4sdecd.dll version < 11.0.6001.7009
    checkVer = "11.0.6001.7009";
  }
  else if("Service Pack 2" >< SP)
  {
    ## Mp4sdecd.dll version < 11.0.6002.18236
    checkVer = "11.0.6002.18236";
  }

  ## Get system32 Path
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                            item:"PathName");
  if(!sysPath){
    exit(0);
  }

  ## Get File Version
  dllVer = get_file_version(dllPath:sysPath,file_name:"\system32\Mp4sdecd.dll");
  if(!dllVer){
    exit(0);
  }

  ## Check file version less than "checkVer" variable
  if(version_is_less(version:dllVer, test_version:checkVer)){
    security_hole(0);
  }
  exit(0);
}
