###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_digital_cretificate_timestamp_issue.nasl 12 2013-10-27 11:15:33Z jan $
#
# Compatibility Issues Affecting Signed Microsoft Binaries (2749655)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "This could cause compatibility issues between affected binaries and
  Microsoft Windows and This issue could adversely impact the ability to properly
  install and uninstall affected Microsoft components and security updates.
  Impact Level: System";
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior
  Microsoft Windows XP x64 Edition Service Pack 2 and prior
  Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "Issue involving binaries that were signed with digital certificates generated
  by Microsoft without proper timestamp attributes. This issue is caused by a
  missing timestamp Enhanced Key Usage (EKU) extension during certificate
  generation and signing of Microsoft core components and software.";
tag_solution = "Apply the Patch from below link,
  http://technet.microsoft.com/en-us/security/advisory/2749655";
tag_summary = "The host is installed with Microsoft Windows operating system and
  its missing upates according to Microsoft Security Advisory (2749655)";

if(description)
{
  script_id(802468);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"risk_factor", value:"None");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-11 17:15:51 +0530 (Thu, 11 Oct 2012)");
  script_name("Compatibility Issues Affecting Signed Microsoft Binaries (2749655)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2749655");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2756872");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2749655");

  script_description(desc);
  script_summary("Check for the vulnerable Wintrust.dll file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
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
dllVer = "";
sysPath = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
                   win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Wintrust.dll file
dllVer = fetch_file_version(sysPath, file_name:"system32\Wintrust.dll");
if(!dllVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Wintrust.dll version before 5.131.2600.6285
  if(version_is_less(version:dllVer, test_version:"5.131.2600.6285")){
    log_message(data:desc);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Check for Wintrust.dll version before 5.131.3790.5014
  if(version_is_less(version:dllVer, test_version:"5.131.3790.5060")){
    log_message(data:desc);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Wintrust.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.6002.18686") ||
     version_in_range(version:dllVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22919")){
    log_message(data:desc);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Wintrust.dll version
  if(version_is_less(version:dllVer, test_version:"6.1.7600.17115") ||
     version_in_range(version:dllVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21312")||
     version_in_range(version:dllVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17939")||
     version_in_range(version:dllVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22098")){
    log_message(data:desc);
  }
}
