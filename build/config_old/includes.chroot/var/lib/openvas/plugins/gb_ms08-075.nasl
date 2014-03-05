###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-075.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows Search Remote Code Execution Vulnerability (959349)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will let the remote attackers attackers to execute
  arbitrary code.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista Service Pack 1 and prior.
  Microsoft Windows Server 2008 Service Pack 1 and prior.";
tag_insight = "The flaws are due to
  - an error in Windows Explorer that does not correctly free memory when
    saving Windows Search files.
  - an error in Windows Explorer that does not correctly interpret
    parameters when parsing the search-ms protocol.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-075.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-075.";

if(description)
{
  script_id(801483);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-14 06:32:32 +0100 (Tue, 14 Dec 2010)");
  script_cve_id("CVE-2008-4268", "CVE-2008-4269");
  script_bugtraq_id(32651, 32652);
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Windows Search Remote Code Execution Vulnerability (959349)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33053/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/3387");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-075.mspx");
 
  script_description(desc);
  script_summary("Check for the version of Explorer.exe file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:2, win2008:2) <= 0){
  exit(0);
}

## Check Hotfix MS08-075
if(hotfix_missing(name:"958624") == 1)
{
  ## Get System32 path
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
  if(sysPath)
  {
    exeVer = get_file_version(sysPath, file_name:"Explorer.exe");
    if(exeVer)
    {
      # Windows Vista
      if(hotfix_check_sp(winVista:2) > 0)
      {
        SP = get_kb_item("SMB/WinVista/ServicePack");
        if("Service Pack 1" >< SP)
        {
          # Grep for Explorer.exe version < 6.0.6001.18164
          if(version_is_less(version:exeVer, test_version:"6.0.6001.18164")){
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
          # Grep for Explorer.exe version < 6.0.6001.18164
          if(version_is_less(version:exeVer, test_version:"6.0.6001.18164")){
            security_hole(0);
          }
          exit(0);
        }
      }
    }
  }
}

## Check Hotfix MS08-075
if(hotfix_missing(name:"958623") == 1)
{
  ## Get System32 path
  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
  if(sysPath)
  {
    dllVer = get_file_version(sysPath, file_name:"System32\shell32.dll");
    if(dllVer)
    {
      # Windows Vista
      if(hotfix_check_sp(winVista:2) > 0)
      {
        SP = get_kb_item("SMB/WinVista/ServicePack");
        if("Service Pack 1" >< SP)
        {
          # Grep for shell32.dll version < 6.0.6001.18167
          if(version_is_less(version:dllVer, test_version:"6.0.6001.18167")){
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
          # Grep for shell32.dll version < 6.0.6001.18167
          if(version_is_less(version:dllVer, test_version:"6.0.6001.18167")){
            security_hole(0);
          }
          exit(0);
        }
      }
    }
  }
}
