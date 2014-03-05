###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-040.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft .NET Framework Authentication Bypass and Spoofing Vulnerabilities (2836440)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
tag_impact = "Successful exploitation could allow an attacker to bypass security mechanism
  and gain access to restricted endpoint functions.
  Impact Level: System/Application";

tag_affected = "Microsoft .NET Framework 4
  Microsoft .NET Framework 4.5
  Microsoft .NET Framework 3.5
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 2.0 Service Pack 2";
tag_insight = "The flaws are due to
  - Improper validation of XML signatures by the CLR
  - Error within the WCF endpoint authentication mechanism when handling
    queries";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-040";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-040.";

if(description)
{
  script_id(903308);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1336", "CVE-2013-1337");
  script_bugtraq_id(59789, 59790);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-15 12:23:29 +0530 (Wed, 15 May 2013)");
  script_name("Microsoft .NET Framework Authentication Bypass and Spoofing Vulnerabilities (2836440)");
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
  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.com/93301");
  script_xref(name : "URL" , value : "http://www.osvdb.com/93302");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53350");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-040");
  script_summary("Check for the version of 'System.Security.dll' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
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
dllVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

## Confirm .NET
key = "SOFTWARE\Microsoft\ASP.NET\";
if(registry_key_exists(key:key))
{
  ## Try to Get Version
  foreach item (registry_enum_keys(key:key))
  {
    path = registry_get_sz(key:key + item, item:"Path");
    if(path && "\Microsoft.NET\Framework" >< path)
    {
      ## Get version from System.dll file
      dllVer = fetch_file_version(sysPath:path, file_name:"System.Security.dll");

      ## .NET Framework 4.5 and 3.5 on Windows 8 and Windows Server 2012
      if(dllVer && (hotfix_check_sp(win8:1, win2012:1) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18038")||
           version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19057")||
           version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6403")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7017"))
        {
          security_hole(0);
          exit(0);
        }
      }

      ## .NET Framework 4.5 , 4.0 and 3.5.1 on Windows 7 Service Pack 1, Windows Server 2008 R2 Service Pack 1
      if(dllVer && (hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5468")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7017")||
           version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1003")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2005")||
           version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18037")||
           version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19056"))
        {
          security_hole(0);
          exit(0);
        }
      }

      ## .NET Framework 4.5, 4.0 and 2.0 SP 2 on Windows Vista and Windows Server 2008
      if(dllVer && (hotfix_check_sp(winVista:3, win2008:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.0000", test_version2:"2.0.50727.4236")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7017")||
           version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1003")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2005")||
           version_in_range(version:dllVer, test_version:"4.0.30319.18000", test_version2:"4.0.30319.18037")||
           version_in_range(version:dllVer, test_version:"4.0.30319.19000", test_version2:"4.0.30319.19056"))
        {
          security_hole(0);
          exit(0);
        }
      }

      ## .NET Framework 4.0 and 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if(dllVer && (hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1003")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2005")||
           version_in_range(version:dllVer, test_version:"2.0.50727.0000", test_version2:"2.0.50727.3645")||
           version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7018"))
        {
          security_hole(0);
          exit(0);
        }
      }
    }
  }
}
