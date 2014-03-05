###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-035.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft .NET Framework Remote Code Execution Vulnerability (2693777)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary code
  with the privileges of the currently logged-in user. Failed attacks will
  cause denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "Microsoft .NET Framework 1.0 SP3, 1.1 SP1, 2.0 SP2, 3.0 SP2, 3.5 SP1, 3.5.1,
  and 4";
tag_insight = "The flaws are due to
  - An error within the .NET Framework does not properly serialize user input
    and can be exploited to treat untrusted input as trusted.
  - An error within the .NET Framework does not properly handle exceptions when
    serializing objects and can be exploited via partially trusted assemblies.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-035";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-035.";

if(description)
{
  script_id(902833);
  script_version("$Revision: 12 $");
  script_bugtraq_id(53356, 53357);
  script_cve_id("CVE-2012-0160", "CVE-2012-0161");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-09 16:16:16 +0530 (Wed, 09 May 2012)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (2693777)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49117");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2693777");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027036");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-035");

  script_description(desc);
  script_summary("Check for the version of vulnerable files");
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

## Variables Initialization
key = "";
item = "";
path = "";
dllVer = NULL;
sysVer = NULL;
sysPath = "";

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
  if(path && "\Microsoft.NET\Framework" >< path)
  {
    ## Get version from System.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"System.dll");
    if(dllVer)
    {
      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
      ##  Windows 7 and and Windows Server 2008 R2
      if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.268")||
         version_in_range(version:dllVer, test_version:"4.0.30319.500", test_version2:"4.0.30319.543"))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5455")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5709")||
          version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4970")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4222")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5709")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3633")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.5709")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 1.1 Service Pack 1 on Windows XP, Windows Server 2003, Windows Vista and Windows Server 2008
      if((hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2493")))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}

## Get System Path
sysPath = smb_get_systemroot();
if(! sysPath){
  exit(0);
}

## .NET Framework 3.0 Service Pack 2
key = "SOFTWARE\Microsoft\.NETFramework\AssemblyFolders\v3.0";
if(registry_key_exists(key:key))
{
  ## Get Version from XPSViewer.exe
  sysVer = fetch_file_version(sysPath, file_name:"system32\XPSViewer\XPSViewer.exe");
  if(sysVer)
  {
    ## .NET Framework 3.0 Service Pack 2 on Windows Vista and Windows Server 2008
    if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
      (version_in_range(version:sysVer, test_version:"3.0.6920.0", test_version2:"3.0.6920.4205")||
       version_in_range(version:sysVer, test_version:"3.0.6920.5000", test_version2:"3.0.6920.5737")))
    {
      security_hole(0);
      exit(0);
    }

    ## .NET Framework 3.0 Service Pack 2 on Windows XP and Windows Server 2003
    if((hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0) &&
       (version_in_range(version:sysVer, test_version:"3.0.6920.0", test_version2:"3.0.6920.4020")||
        version_in_range(version:sysVer, test_version:"3.0.6920.5000", test_version2:"3.0.6920.5809")))
    {
      security_hole(0);
      exit(0);
    }
  }
}
