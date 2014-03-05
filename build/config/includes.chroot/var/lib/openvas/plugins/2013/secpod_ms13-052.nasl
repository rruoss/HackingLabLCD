###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-052.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft .NET Framework Multiple Vulnerabilities (2861561)
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
tag_impact = "
  Impact Level: System";

if(description)
{
  script_id(902985);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133",
                "CVE-2013-3134", "CVE-2013-3171");
  script_bugtraq_id(60978, 60932, 60933, 60934, 60935, 60937);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-10 12:28:17 +0530 (Wed, 10 Jul 2013)");
  script_name("Microsoft .NET Framework Multiple Vulnerabilities (2861561)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-052.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws due to,
- Improper handling of TrueType font and multidimensional arrays of small
  structures
- Improper validation of permissions for certain objects performing reflection
  and delegate objects during serialization";

  tag_impact =
"Successful exploitation could allow an attacker to execute arbitrary code,
bypass security mechanism and take complete control of an affected system.";

  tag_affected =
"Microsoft .NET Framework 1.0, 1.1, 2.0, 3.0, 3.5, 3.5.1, 4.0 and 4.5";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms13-052";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/94960");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54025");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2861561");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-052");
  script_summary("Check for the version of vulnerable files");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
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
dllVer = "";
dllv4 = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1) <= 0){
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
    dllVer = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(dllVer)
    {
      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
      ##  Windows 7 and and Windows Server 2008 R2
      if(version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1007")||
         version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2011"))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 4.5 on Windows 7 SP1 and Windows Server 2008 R2 SP 1
      ##  Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18051")||
          version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19079")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 4.5 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18050")||
          version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19078")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5471")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7024")))
      {
        security_hole(0);
        exit(0);
      }

      ##  .NET Framework 3.5 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6406")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7024")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4240")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7024")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3648")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7025")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 1.1 Service Pack 1 on Windows XP, Windows Server 2003, Windows Vista and Windows Server 2008
      if((hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2502")))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}


foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    ## Get version from System.configuration.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"System.configuration.dll");
    if(dllVer)
    {
      ## NET Framework 2.0 Service Pack 2 Windows XP, Windows Server 2003,
      ## Windows Vista and Windows Server 2008
      ## updated on Aug-16-2013 (2.0.50727.4246) (2.0.50727.7035) (2.0.50727.3654) (2.0.50727.7037)
      if(hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3653")||
           version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4245") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7034") ||
           version_in_range(version:dllVer, test_version:"2.0.50727.5700", test_version2:"2.0.50727.7036"))
        {
          security_hole(0);
          exit(0);
        }
      }

       # .NET Framework 3.5 on Windows 8 and Windows Server 2012
       ## updated on Aug-16-2013 (2.0.50727.6411) (2.0.50727.7035)
       if(hotfix_check_sp(win8:1, win2012:1) > 0)
       {
         if(version_in_range(version:dllVer, test_version:"2.0.50727.6400", test_version2:"2.0.50727.6410") ||
            version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7034"))
         {
           security_hole(0);
           exit(0);
         }
       }

      ## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
      ## Updated on Aug-16-2013 (2.0.50727.5476) (2.0.50727.7035)
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5475")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7034")))
      {
        security_hole(0);
        exit(0);
      }

      ##  .NET Framework 4.5 on Windows 8, and Windows Server 2012
      ##  Updated on Aug-16-2013(4.0.30319.18058) (4.0.30319.19112)
      if((hotfix_check_sp(win8:1, win2012:1) > 0))
      {
         if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18057") ||
            version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19111"))
         {
           security_hole(0);
           exit(0);
         }
       }
    }
  }
}


##.NET Framework 3.5 on Windows 8 and Windows Server 2012
foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    ## Get version from System.printing.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"System.printing.dll");
    if(dllVer)
    {
      ## .NET Framework 3.5 on Windows 8 and Windows Server 2012
      if(hotfix_check_sp(win8:1, win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"3.0.6920.6400", test_version2:"3.0.6920.6401")||
           version_in_range(version:dllVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7035"))
        {
          security_hole(0);
          exit(0);
        }
      }

     ## Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
     if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"3.0.6920.5400", test_version2:"3.0.6920.5452")||
          version_in_range(version:dllVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7035")))
      {
        security_hole(0);
        exit(0);
      }
     }
   }
}

# .NET Framework 3.5 Service Pack 1 on Windows XP Service Pack 3,
## Windows Server 2003 Service Pack 2, Windows Vista Service Pack 2,
## and Windows Server 2008 Service Pack 2
foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    ## Get version from System.Data.Linq.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"System.Data.Linq.dll");
    if(dllVer)
    {
      ## .NET Framework 3.5 Service Pack 1 on Windows XP Service Pack 3, Windows Server 2003
      ## Service Pack 2, Windows Vista Service Pack 2, and Windows Server 2008 Service Pack 2
      if(hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"3.5.30729.4000", test_version2:"3.5.30729.4051")||
           version_in_range(version:dllVer, test_version:"3.0.30729.7000", test_version2:"3.5.30729.7048"))
        {
          security_hole(0);
          exit(0);
        }
      }

      ##  .NET Framework 3.5 on Windows 8 and Windows Server 2012
      if(hotfix_check_sp(win8:1, win2012:1) > 0)
      {
        if(version_in_range(version:dllVer, test_version:"3.5.30729.6400", test_version2:"3.5.30729.6403")||
           version_in_range(version:dllVer, test_version:"3.5.30729.7000", test_version2:"3.5.30729.7047"))
        {
          security_hole(0);
          exit(0);
        }
       }

      ## .NET Framework 3.5.1 on Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"3.5.30729.5400", test_version2:"3.5.30729.5454")||
          version_in_range(version:dllVer, test_version:"3.5.30729.7000", test_version2:"3.5.30729.7047")))
      {
        security_hole(0);
        exit(0);
      }
     }
   }
}


## Get System Path
sysPath = smb_get_systemroot();
if(sysPath)
{
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
        (version_in_range(version:sysVer, test_version:"3.0.6920.4200", test_version2:"3.0.6920.4215")||
         version_in_range(version:sysVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7035")))
      {
        security_hole(0);
        exit(0);
      }

      ## .NET Framework 3.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:sysVer, test_version:"3.0.6920.4000", test_version2:"3.0.6920.4049")||
         version_in_range(version:sysVer, test_version:"3.0.6920.7000", test_version2:"3.0.6920.7044")))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}

## Get .NET Framework 4.0 Version
key = "SOFTWARE\Microsoft\ASP.NET\4.0.30319.0";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"Path");
  if(path){
    dllv4 = fetch_file_version(sysPath:path, file_name:"WPF\Presentationcore.dll");
  }
}

## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
if(hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllv4, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1004") ||
     version_in_range(version:dllv4, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2008"))
  {
    security_hole(0);
    exit(0);
  }
}

##.NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista,
## Windows Server 2008, Windows 7, and Windows Server 2008
## Updated on Aug-16-2013 (4.0.30319.1015)(4.0.30319.2022)
if(hotfix_check_sp(xp:4, win2003:3, win2003x64:3, winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllv4, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1014") ||
     version_in_range(version:dllv4, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2021"))
  {
    security_hole(0);
    exit(0);
  }
}

## .NET Framework 4.5 on Windows 7 SP1 and Windows Server 2008 R2 SP 1
##  Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
## updated on Aug-16-2013 (4.0.30319.18060), (4.0.30319.19115)
if(dllv4)
{
  if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
     version_in_range(version:dllv4, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18059") ||
     version_in_range(version:dllv4, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19114"))
   {
     security_hole(0);
     exit(0);
   }
}

## .NET Framework 4.5 on Windows Vista Service Pack 2 and
##  Windows Server 2008 Service Pack 2
key = "SOFTWARE\Microsoft\ASP.NET\4.0.30319.0";
if(registry_key_exists(key:key))
{
  path = registry_get_sz(key:key, item:"Path");
  if(path){
    dllv4 = fetch_file_version(sysPath:path, file_name:"WPF\Wpftxt_v0400.dll");
  }
}

## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008,
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllv4, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18048") ||
     version_in_range(version:dllv4, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19076"))
  {
    security_hole(0);
    exit(0);
  }
}
