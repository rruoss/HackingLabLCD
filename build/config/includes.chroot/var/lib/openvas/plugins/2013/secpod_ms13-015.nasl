###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-015.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft .NET Framework Privilege Elevation Vulnerability (2800277)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code.
  Impact Level: System/Application";

tag_affected = "Microsoft .NET Framework 4
  Microsoft .NET Framework 4.5
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 2.0 Service Pack 2";
tag_insight = "The flaw is due to an error when handling permissions of a callback function
  when a certain WinForm object is created and can be exploited to bypass CAS
  (Code Access Security) restrictions via a specially crafted XAML Browser
  Application (XBAP) or an untrusted .NET application.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-015";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-015.";

if(description)
{
  script_id(902950);
  script_version("$Revision: 11 $");
  script_bugtraq_id(57847);
  script_cve_id("CVE-2013-0073");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-13 13:21:23 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft .NET Framework Privilege Elevation Vulnerability (2800277)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52143/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2800277");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-015");

  script_description(desc);
  script_summary("Check for the version of 'system.windows.forms.dll' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
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

## Variables Initialization
path = "";
dllv4 = NULL;
dllv2 = NULL;

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Confirm .NET
key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Try to Get Version
foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    if("v4.0.30319" >< path){
      dllv4 = fetch_file_version(sysPath:path, file_name:"system.windows.forms.dll");
    }

    if("v2.0.50727" >< path){
      dllv2 = fetch_file_version(sysPath:path, file_name:"system.windows.forms.dll");
    }
  }
}

## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista,
##  Windows Server 2008, Windows 7, and Windows Server 2008 R2
if(dllv4 &&
  (version_in_range(version:dllv4, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1001") ||
   version_in_range(version:dllv4, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2002")))
{
  security_hole(0);
  exit(0);
}

## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
if(dllv2 && (hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.4985") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7014") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5467"))
  {
    security_hole(0);
    exit(0);
  }
}

## .NET Framework 2.0 SP 2 on Windows Vista Service and Windows Server 2008
if(dllv2 && (hotfix_check_sp(winVista:3, win2008:3) > 0))
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.4235") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7014"))
  {
    security_hole(0);
    exit(0);
  }
}

## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
if(dllv2 && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
{
  if(version_in_range(version:dllv2, test_version:"2.0.50727.0000", test_version2:"2.0.50727.3644") ||
     version_in_range(version:dllv2, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7014"))
  {
    security_hole(0);
    exit(0);
  }
}

## .NET Framework 4.5 on Windows 7 Service Pack 1, Windows Server 2008 R2
## Service Pack 1, Windows Vista Service Pack 2, and Windows Server 2008 Service Pack 2
if(dllv4 && (hotfix_check_sp(win7:2, win2008:3, win7x64:2, win2008r2:2, winVista:3) > 0))
{
  if(version_in_range(version:dllv4, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18035") ||
     version_in_range(version:dllv4, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19051"))
  {
    security_hole(0);
    exit(0);
  }
}
