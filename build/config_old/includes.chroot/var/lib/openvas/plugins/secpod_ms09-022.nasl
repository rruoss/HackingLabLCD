###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-022.nasl 15 2013-10-27 12:49:54Z jan $
#
# Vulnerabilities in Print Spooler Could Allow Remote Code Execution (961501)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
# 
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-01
#       - To detect file version 'localspl.dll' on vista and win 2008
#
# Copyright (c) 2009 SecPod, http://www.secpod.org
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
tag_impact = "Successful exploitation could allow remote or Local attackers to disclose
  sensitive information or compromise a vulnerable system.
  Impact Level: System";
tag_affected = "Microsoft Windows 2003 Service Pack 2.
  Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The multiple flaws are due to,
  - Buffer overflow error in the Windows Print Spooler when parsing certain
    printing data structures, via a specially crafted RPC request and a
    malicious print server.
  - Error in the Windows Printing Service that does not properly check the files
    that can be included with separator pages.
  - Error in the Windows Print Spooler that does not properly validate the paths
    from which a DLL may be loaded.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-022.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-022.";

if(description)
{
  script_id(900667);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-10 16:35:14 +0200 (Wed, 10 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0228", "CVE-2009-0229", "CVE-2009-0230");
  script_bugtraq_id(35206,35208,35209);
  script_name("Vulnerabilities in Print Spooler Could Allow Remote Code Execution (961501)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1541");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-022.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# Check Hotfix Missing 961501 (MS09-022)
if(hotfix_missing(name:"961501") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"localspl.dll");
  if(!sysVer){
      exit(0);
  }
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Localspl.dll  version < 5.0.2195.7296
    if(version_is_less(version:sysVer, test_version:"5.0.2195.7296")){
      security_hole(0);
  }
   exit(0);
}

# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Localspl.dll < 5.1.2600.3569
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3569")){
      security_hole(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Localspl.dll < 5.1.2600.5809
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5809")){
      security_hole(0);
    }
     exit(0);
  }
  security_hole(0);
}

# Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Localspl.dll version < 5.2.3790.4509
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4509")){
      security_hole(0);
    }
     exit(0);
  }
  security_hole(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{
  dllVer = get_file_version(sysPath, file_name:"System32\Localspl.dll");
  if(!dllVer){
    exit(0);
  }
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Localspl.dll version < 6.0.6001.18247
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
        security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Localspl.dll version < 6.0.6002.18024
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
      security_hole(0);
    }
     exit(0);
  }
  security_hole(0);
}

# Windows Server 2008
else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Localspl.dll version < 6.0.6001.18247
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18247")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Localspl.dll version < 6.0.6002.18024
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18024")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}

