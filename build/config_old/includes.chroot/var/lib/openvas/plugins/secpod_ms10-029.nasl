###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-029.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft 'ISATAP' Component Spoofing Vulnerability (978338)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-17
#        - To detect file version 'Tcpip.sys' on vista and 2008 server
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
tag_impact = "Successful exploitation could allow remote attackers to spoof IPv6
  addresses and information disclosure and other attacks may also be
  possible.
  Impact Level: System";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaw is due to an error in 'ISATAP' Component when handling 'IPv4'
  address, allows an attacker to spoof an IPv6 address so that it can bypass
  filtering devices that rely on the source IPv6 address.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-029.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-029.";

if(description)
{
  script_id(902157);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_cve_id("CVE-2010-0812");
  script_bugtraq_id(39352);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_name("Microsoft 'ISATAP' Component Spoofing Vulnerability (978338)");
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
  script_xref(name : "URL" , value : "http://isc.sans.org/diary.html?storyid=8626");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-029.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable 'Tcpip6.sys' file version");
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

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# Check for MS10-029 Hotfix
if(hotfix_missing(name:"978338") == 0){
  exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"drivers\Tcpip6.sys");
  if(!sysVer){
    exit(0);
  }
}

# Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Tcpip6.sys < 5.1.2600.3667
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3667")){
      security_hole(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Tcpip6.sys < 5.1.2600.5935
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5935")){
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
    # Grep for Tcpip6.sys version < 5.2.3790.4662
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4662")){
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
  sysVer = get_file_version(sysPath, file_name:"System32\drivers\Tcpip.sys");
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
    # Grep for Tcpip.sys version < 6.0.6001.18427
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18427")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Tcpip.sys version < 6.0.6002.18209
      if(version_is_less(version:sysVer, test_version:"6.0.6002.18209")){
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
    # Grep for Tcpip.sys version < 6.0.6001.18427
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18427")){
      security_hole(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Tcpip.sys version < 6.0.6002.18209
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18209")){
      security_hole(0);
    }
    exit(0);
  }
 security_hole(0);
}
