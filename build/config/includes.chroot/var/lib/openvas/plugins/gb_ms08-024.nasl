###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-024.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Internet Explorer Data Stream Handling Remote Code Execution Vulnerability (947864)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary code with
  the privileges of the application. Failed attacks may cause denial-of-service
  conditions.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 5.x/6.x/7.x";
tag_insight = "The flaw is due to a memory corruption error in Internet Explorer when
  processing specially crafted data streams.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-024.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-024.";

if(description)
{
  script_id(801488);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-10 14:22:58 +0100 (Mon, 10 Jan 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-1085");
  script_bugtraq_id(28552);
  script_name("Microsoft Internet Explorer Data Stream Handling Remote Code Execution Vulnerability (947864)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/27707");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/1148/references");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-024.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable mshtml.dll file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:2, win2008:2) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS08-024 Hotfix (947864)
if(hotfix_missing(name:"947864") == 0){
    exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  vers = get_file_version(sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      # Check for mshtml.dll version 5.0 < 5.0.3862.1500, 6.0 < 6.0.2800.1609
      if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3862.1499") ||
         version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1608")){
         security_hole(0);
      }
      exit(0);
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.2900.3314, 7.0 < 7.0.6000.16640
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2900.3313") ||
           version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16639")){
          security_hole(0);
        }
        exit(0);
      }
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.3790.3091
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.3090")){
          security_hole(0);
        }
        exit(0);
      }

      if("Service Pack 2" >< SP)
      {
        # Check for mshtml.dll version 6.0 < 6.0.3790.4237, 7.0 < 7.0.6000.16640
        if(version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4236") ||
           version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.16639")){
          security_hole(0);
        }
        exit(0);
      }
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
if(dllVer)
{
  # Windows Vista
  if(hotfix_check_sp(winVista:3) > 0)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep for mshtml.dll version
      if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18022")){
        security_hole(0);
      }
      exit(0);
    }
  }

  # Windows Server 2008
  else if(hotfix_check_sp(win2008:3) > 0)
  {
    SP = get_kb_item("SMB/Win2008/ServicePack");
    if("Service Pack 1" >< SP)
    {
      # Grep for mshtml.dll version
      if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18022")){
         security_hole(0);
      }
      exit(0);
    }
  }
}

