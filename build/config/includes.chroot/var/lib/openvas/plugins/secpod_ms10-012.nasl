###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-012.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows SMB Server Multiple Vulnerabilities (971468)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-22
#   - To detect file version 'srv.sys' on vista, win 2008 and win 7
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause a denial of service or bypass the authentication mechanism
  via brute force technique.
  Impact Level: System/Application";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows 2K  Service Pack 4 and prior
  Microsoft Windows XP  Service Pack 3 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "- An input validation error exists while processing SMB requests and can
    be exploited to cause a buffer overflow via a specially crafted SMB packet.
  - An error exists in the SMB implementation while parsing SMB packets during
    the Negotiate phase causing memory corruption via a specially crafted SMB
    packet.
  - NULL pointer dereference error exists in SMB while verifying the 'share'
    and 'servername' fields in SMB packets causing denial of service.
  - A lack of cryptographic entropy when the SMB server generates challenges
    during SMB NTLM authentication and can be exploited to bypass the
    authentication mechanism.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-012.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-012.";

if(description)
{
  script_id(900230);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-02-10 16:06:43 +0100 (Wed, 10 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-0020", "CVE-2010-0021",
                "CVE-2010-0022", "CVE-2010-0231");
  script_name("Microsoft Windows SMB Server Multiple Vulnerabilities (971468)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38510/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/971468");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0345");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-012.mspx");

  script_description(desc);
  script_summary("Check for the version of Srv.sys file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

## Check Hotfix MS10-012
if(hotfix_missing(name:"971468") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"drivers\Srv.sys");
  if(!sysVer){
    exit(0);
  }
}

## Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  ## Grep for Srv.sys version < 5.0.2195.7365
  if(version_is_less(version:sysVer, test_version:"5.0.2195.7365")){
    security_hole(0);
  }
   exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Grep for Srv.sys < 5.1.2600.3662
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3662")){
      security_hole(0);
    }
     exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    ## Grep for Srv.sys < 5.1.2600.5923
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5923")){
      security_hole(0);
    }
     exit(0);
  }
  security_hole(0);
}

## Windows 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Grep for Srv.sys version < 5.2.3790.4634
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4634")){
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
  sysVer = get_file_version(sysPath, file_name:"System32\drivers\Srv.sys");
  if(!sysVer){
    exit(0);
  }
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Srv.sys version < 6.0.6001.18381
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18381")){
      security_hole(0);
    }
      exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Srv.sys version < 6.0.6002.18164
      if(version_is_less(version:sysVer, test_version:"6.0.6002.18164")){
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
    # Grep for Srv.sys version < 6.0.6001.18381
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18381")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Srv.sys version < 6.0.6002.18164
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18164")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for Srv.sys version < 6.1.7600.16481
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16481")){
     security_hole(0);
  }
}

