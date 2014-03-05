###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-016.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft .NET Framework and Microsoft Silverlight Remote Code Execution Vulnerabilities (2651026)
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
tag_impact = "Successful exploitation could allow attacker to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will likely
  result in a denial-of-service condition.
  Impact Level: System/Application";
tag_affected = "Microsoft Silverlight 4.0
  Microsoft .NET Framework 4.0
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 2.0 Service Pack 2";
tag_insight = "Multiple flaws are due to
  - An unspecified error when handling un-managed objects can be exploited via
    a specially crafted XAML Browser Application (XBAP).
  - An error when calculating certain buffer lengths can be exploited to corrupt
    memory via a specially crafted XAML Browser Application (XBAP).";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-016";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-016.";

if(description)
{
  script_id(902811);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0014", "CVE-2012-0015");
  script_bugtraq_id(51938, 51940);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-02-15 10:10:10 +0530 (Wed, 15 Feb 2012)");
  script_name("Microsoft .NET Framework and Microsoft Silverlight Remote Code Execution Vulnerabilities (2651026)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48030");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2651026");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026681");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-016");

  script_description(desc);
  script_summary("Check for the version of 'System.dll' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_silverlight_detect.nasl");
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
mslVer = NULL;

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## Get Silverlight version from KB
mslVer = get_kb_item("Microsoft/Silverlight");
if(mslVer)
{
  ## Check for Microsoft Silverlight version prior to 4.1.10111
  if(version_is_less(version:mslVer, test_version:"4.1.10111"))
  {
    security_hole(0);
    exit(0);
  }
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
      ## .NET Framework 4 on Windows XP, Windows Server 2003, Windows Vista, Windows Server 2008, Windows 7
      if((hotfix_missing(name:"2633870") == 1))
      {
        if(version_in_range(version:dllVer, test_version:"4.0.30319.000", test_version2:"4.0.30319.257")||
           version_in_range(version:dllVer, test_version:"4.0.30319.500", test_version2:"4.0.30319.522"))
        {
          security_hole(0);
          exit(0);
        }
      }

      ## .NET Framework 3.5.1 on Windows 7
      if(((hotfix_missing(name:"2633873") == 1) ||
         (hotfix_missing(name:"2633879") == 1)) && (hotfix_check_sp(win7:2) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4967")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5452")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5702"))
        {
          security_hole(0);
          exit(0);
        }
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_missing(name:"2633874") == 1) &&
         (hotfix_check_sp(winVista:3, win2008:3) > 0))
     {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4219")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5702"))
        {
          security_hole(0);
          exit(0);
        }
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows XP and Windows Server 2003
      if((hotfix_missing(name:"2633880") == 1) &&
         (hotfix_check_sp(xp:4, win2003:3) > 0))
      {
        if(version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3630")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5703"))
        {
          security_hole(0);
          exit(0);
        }
      }
    }
  }
}
