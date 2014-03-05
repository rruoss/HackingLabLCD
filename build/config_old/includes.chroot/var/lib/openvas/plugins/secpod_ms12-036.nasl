###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-036.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Remote Desktop Protocol Remote Code Execution Vulnerability (2685939)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code as the logged-on user or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "The way that the Remote Desktop Protocol accesses an object in memory that
  has been improperly initialized or has been deleted or the way RDP service
  processes the packets, allows to run arbitrary code on the target system.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-036";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-036.";

if(description)
{
  script_id(902683);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0173");
  script_bugtraq_id(53826);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-13 11:36:15 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft Remote Desktop Protocol Remote Code Execution Vulnerability (2685939)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49384");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2685939");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027148");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/49384");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-036");

  script_description(desc);
  script_summary("Check for the vulnerable 'Rdpwd.sys' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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
sysPath = "";
rdpVer = "";

## Check for OS and Service Pack
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Rdpwd.sys file
rdpVer = fetch_file_version(sysPath, file_name:"system32\drivers\Rdpwd.sys");
if(!rdpVer){
  exit(0);
}

# Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  # Check for Rdpwd.sys version < 5.1.2600.6221
  if(version_is_less(version:rdpVer, test_version:"5.1.2600.6221")){
     security_hole(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Rdpwd.sys version before 5.2.3790.4996
  if(version_is_less(version:rdpVer, test_version:"5.2.3790.4996")){
    security_hole(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Rdpwd.sys version
  if(version_is_less(version:rdpVer, test_version:"6.0.6002.18621") ||
     version_in_range(version:rdpVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22843")){
    security_hole(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Rdpwd.sys versions
  if(version_is_less(version:rdpVer, test_version:"6.1.7600.17011") ||
     version_in_range(version:rdpVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21201")||
     version_in_range(version:rdpVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17829")||
     version_in_range(version:rdpVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.21981")){
    security_hole(0);
  }
}
