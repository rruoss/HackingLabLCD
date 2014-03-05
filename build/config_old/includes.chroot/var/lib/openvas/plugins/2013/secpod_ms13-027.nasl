###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-027.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2807986)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to compromise the
  affected system and possibly execute arbitrary code with System-level
  privileges.
  Impact Level: System";

tag_affected = "Microsoft Windows 7 x32/x64 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 2003 x32/x64 Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Service Pack 2 and prior
  Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";
tag_insight = "Multiple flaws are due to improper handling of objects in memory by the
  kernel-mode driver, which can be exploited by inserting a malicious USB
  device into the system.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS13-027";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-027.";

if(description)
{
  script_id(903200);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1285", "CVE-2013-1286","CVE-2013-1287");
  script_bugtraq_id(58359, 58360, 58361);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-13 09:16:53 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft Windows Kernel-Mode Drivers Privilege Elevation Vulnerabilities (2807986)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/91155");
  script_xref(name : "URL" , value : "http://www.osvdb.org/91156");
  script_xref(name : "URL" , value : "http://www.osvdb.org/91157");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2807986");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS13-027");

  script_description(desc);
  script_summary("Check for the vulnerable 'Usb8023.sys' file version");
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
sysPath = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Usb8023.sys file
sysVer = fetch_file_version(sysPath, file_name:"\system32\drivers\usb8023.sys");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Usb8023.sys version before 5.1.2600.6352
  if(version_is_less(version:sysVer, test_version:"5.1.2600.6352")){
    security_hole(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Usb8023.sys version before 5.2.3790.5123
  if(version_is_less(version:sysVer, test_version:"5.2.3790.5123")){
    security_hole(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Usb8023.sys version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18782") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23037")){
    security_hole(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Usb8023.sys version
  if(version_is_less(version:sysVer, test_version:"6.1.7600.17233") ||
     version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21443")||
     version_in_range(version:sysVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18075")||
     version_in_range(version:sysVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22247")){
    security_hole(0);
  }
}
