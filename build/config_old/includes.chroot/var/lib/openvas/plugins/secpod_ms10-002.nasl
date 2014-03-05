###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-002.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (978207)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-22
#  - To detect file version 'mshtml.dll' on vista, win 2008 and win 7
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary codes via
  specially crafted HTML page in the context of the affected system and cause
  memory corruption.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 5.x/6.x/7.x/8.x";
tag_insight = "The Multiple flaws are due to:
  - Use-after-free error in the 'mshtml.dll' library
  - Input validation error when processing URLs, which could allow a
    malicious web site to execute a binary from the local client system
  - Memory corruption error when the browser accesses certain objects,
    which could be exploited by remote attackers to execute arbitrary code
  - Browser disabling an HTML attribute in appropriately filtered response
    data, which could be exploited to execute script in the context of the
    logged-on user in a different Internet domain.
  - Error when the browser attempts to access incorrectly initialized
    memory which could be exploited by remote attackers to execute arbitrary
    code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS10-002";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-002.";

if(description)
{
  script_id(901097);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-22 16:43:14 +0100 (Fri, 22 Jan 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-4074", "CVE-2010-0027", "CVE-2010-0244", "CVE-2010-0245",
                "CVE-2010-0246", "CVE-2010-0247", "CVE-2010-0248", "CVE-2010-0249");
  script_bugtraq_id(37883, 37135, 37884, 37891, 37895, 37892, 37893, 37894, 37815);
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (978207)");
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
  script_summary("Check for the vulnerable mshtml.dll file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0187");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS10-002");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS10-002 Hotfix (978207)
if(hotfix_missing(name:"978207") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"mshtml.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for mshtml.dll version < 5.0.3884.1600 or 6.0 < 6.0.2800.1644
      if(version_in_range(version:dllVer, test_version:"5.0", test_version2:"5.0.3884.1599") ||
         version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.2800.1643"))
      {
        security_hole(0);
        exit(0);
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.2900.3660
        if(version_in_range(version: dllVer, test_version:"6.0", test_version2:"6.0.2900.3659")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16980")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21182")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18875")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22966")){
           security_hole(0);
    	}
        exit(0);
      }
      else if("Service Pack 3" >< SP)
      {
        # Check for mshtml.dll version 6.0.2900.5921, 7 < 7.0.6000.16981 , 8.0 < 8.0.6001.18876
        if(version_in_range(version: dllVer, test_version:"6.0", test_version2:"6.0.2900.5920")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16980")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21182")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18875")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22966")){
           security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }
    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.3790.4639 , 7.0 < 7.0.6000.16981,
        # 8.0 <  8.0.6001.18876
        if(version_in_range(version: dllVer, test_version:"6.0", test_version2:"6.0.3790.4638") ||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.16980")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21182")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18875")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22966")){
           security_hole(0);
        }
        exit(0);
      }
      security_hole(0);
    }
  }
}


## Get System Path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

dllVer = get_file_version(sysPath, file_name:"System32\mshtml.dll");
if(!dllVer){
  exit(0);
}

# Windows Vista and Windows 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for the Vista and server 2008 without SP
  if(version_in_range(version: dllVer, test_version:"7.0.6000.16000", test_version2:"7.0.6000.16981")||
     version_in_range(version: dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21183")||
     version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18881")||
     version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22972"))
  {
    security_hole(0);
    exit(0);
  }

  ## Check for SP1 and SP2

  SP = get_kb_item("SMB/WinVista/ServicePack");

  if(!SP) {
     SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    # Grep for mshtml.dll version
    if(version_in_range(version: dllVer, test_version:"7.0.6001.16000", test_version2:"7.0.6001.18384")||
       version_in_range(version: dllVer, test_version:"7.0.6001.22000", test_version2:"7.0.6001.22584")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18881")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22972")){
       security_hole(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for mshtml.dll version
    if(version_in_range(version: dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18166")||
       version_in_range(version: dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22289")||
       version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18881")||
       version_in_range(version: dllVer, test_version:"8.0.6001.22000", test_version2:"8.0.6001.22972")){
       security_hole(0);
    }
    exit(0);
  }
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for mshtml.dll version
  if(version_in_range(version: dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16489")||
     version_in_range(version: dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.20599")){
     security_hole(0);
  }
}
