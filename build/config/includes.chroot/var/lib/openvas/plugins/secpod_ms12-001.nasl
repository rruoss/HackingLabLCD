###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-001.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Windows Kernel Security Feature Bypass Vulnerability (2644615)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  leveraging memory corruption vulnerabilities in Windows applications.
  Impact Level: System";
tag_affected = "Micorsoft Windows 7 Service Pack 1 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaw is due to an error in the way the kernel (ntdll.dll) loads
  structured exception handling tables and allows bypassing the SafeSEH
  security mechanism. This facilitates easier exploitation of other
  vulnerabilities in affected applications to execute code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-001";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-001.";

if(description)
{
  script_id(902783);
  script_version("$Revision: 12 $");
  script_bugtraq_id(51296);
  script_cve_id("CVE-2012-0001");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"creation_date", value:"2012-01-11 10:01:06 +0530 (Wed, 11 Jan 2012)");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_name("Microsoft Windows Kernel Security Feature Bypass Vulnerability (2644615)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47356/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2644615");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026493");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-001");

  script_description(desc);
  script_summary("Check for the vulnerable 'Ntdll.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS12-001 Hotfix 2644615
if(hotfix_missing(name:"2644615") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version for Ntdll.dll file
dllVer = fetch_file_version(sysPath, file_name:"system32\Ntdll.dll");
if(!dllVer){
  exit(0);
}

## Windows 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Check for Ntdll.dll version before 5.2.3790.4937
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4937")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Ntdll.dll version
    if(version_in_range(version:dllVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.18540")||
       version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22741")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Ntdll.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7600.16915") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21091")||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17724")||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21860")){
    security_hole(0);
  }
}
