###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-094.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Media Decompression Remote Code Execution Vulnerability (2447961)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS10-094.mspx";

tag_impact = "Successful exploitation will allow remote attackers to load crafted DLL
  file and execute any code it contained.
  Impact Level: System";
tag_affected = "Windows Media Encoder 9 with
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaw is present when the Windows Media Encoder incorrectly restricts
  the path used for loading external libraries. An attacker could convince
  a user to open a legitimate '.prx' file that is located in the same network
  directory as a specially crafted dynamic link library (DLL) file.";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-094.";

if(description)
{
  script_id(900267);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-15 14:53:45 +0100 (Wed, 15 Dec 2010)");
  script_bugtraq_id(42855);
  script_cve_id("CVE-2010-3965");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Media Decompression Remote Code Execution Vulnerability (2447961)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2447961");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS10-094.mspx");

  script_description(desc);
  script_summary("Check for the version of Windows Media Encoder and Hotfix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
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
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:dllPath + "\" + file_name);

  dllVer = GetVer(file:file, share:share);
  if(!dllVer){
    return(FALSE);
  }

  return(dllVer);
}

## OS with Hotfix Check
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

## MS10-094 Hotfix check
if(hotfix_missing(name:"2447961") == 0){
  exit(0);
}

## Windows Media Encoder 9 vulnerability
wme9Installed = registry_key_exists(key:"SOFTWARE\Microsoft\Windows" +
                 "\CurrentVersion\Uninstall\Windows Media Encoder 9");
if(wme9Installed)
{
  wmekey = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\wmenc.exe";
  wmeitem = "Path";
  wmePath = registry_get_sz(key:wmekey, item:wmeitem);

  dllVer = get_file_version(dllPath:wmePath, file_name:"wmenc.exe");

  if(dllVer)
  {
    ## Check wmenc.exe version < 9.0.0.3374
    if(version_in_range(version:dllVer, test_version:"9.0",
                                        test_version2:"9.0.0.3373")){
      security_hole(0);
      exit(0);
    }
  }
}
