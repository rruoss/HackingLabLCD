###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-057.nasl 11 2013-10-27 10:12:02Z jan $
#
# Windows Media Format Runtime Remote Code Execution Vulnerability (2847883)
#
# Authors:
# Arun kallavi <karun@secpod.com>
#
# Thanga Prakash S <tprakash@secpod.com> on 2013-08-30
# Updated According to revised Bulletin V3.0 (August 27, 2013)
#
# Copyright (c) 2013 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");

if(description)
{
  script_id(903223);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3127");
  script_bugtraq_id(60980);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-10 12:37:46 +0530 (Wed, 10 Jul 2013)");
  script_name("Windows Media Format Runtime Remote Code Execution Vulnerability (2847883)");

  tag_summary =
"This host is missing a critical security update according to Microsoft
Bulletin MS13-057.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw due to an unspecified error when handling WMV files.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows 8
Microsoft Windows Server 2003
Microsoft Windows XP Service Pack 3 and prior
Microsoft Windows 7 x32 Service Pack 1 and prior
Microsoft Windows Vista x32 Service Pack 2 and prior
Microsoft Windows Server 2008 x32 Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-057";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/94986");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54062");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2847883");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-057");
  script_summary("Check for the version of vulnerable files");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
dllVer = "";
dllVer2 = "";
dllVer3 = "";
SysPath = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3, win8:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Wmvdmod.dll
dllVer = fetch_file_version(sysPath, file_name:"\system32\Wmvdmod.dll");
dllVer2 = fetch_file_version(sysPath, file_name:"\system32\Wmv9vcm.dll");
dllVer3 = fetch_file_version(sysPath, file_name:"\system32\Wmvdecod.dll");
if(!dllVer && !dllVer2 && !dllVer3){
  exit(0);
}

if(hotfix_check_sp(xp:4, win2003:3) > 0)
{
  ## Check Wmvdmod.dll version
  ## updated on Aug-30-2013 for Wmvdmod.dll (9.0.0.4512) (10.0.0.4010) according to V3.0
  if(version_in_range(version:dllVer, test_version:"9.0",test_version2:"9.0.0.4511") ||
     version_in_range(version:dllVer, test_version:"10.0.0.4300",test_version2:"10.0.0.4374") ||
     version_in_range(version:dllVer, test_version:"10.0.0.3700",test_version2:"10.0.0.3705") ||
     version_in_range(version:dllVer, test_version:"10.0.0.4080", test_version2:"10.0.0.4081") ||
     version_in_range(version:dllVer, test_version:"10.0.0.4000", test_version2:"10.0.0.4009") ||
     version_in_range(version:dllVer3, test_version:"11.0", test_version2:"11.0.5721.5286") ||
     version_in_range(version:dllVer2, test_version:"9.0.1", test_version2:"9.0.1.3072")){
    security_hole(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
## Installing the 2803821 update on Windows Vista Service Pack 2
## or Windows Server 2008 Service Pack 2 downgrades the version of
## wmvdecod.dll from 11.0.6001.xxxx to 6.0.6002.yyyy.
## So this version check may not work later
## Might need to revisit later and verify.
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Wmvdecod.dll version
  ## updated on Aug-30-2013 for Wmvdecod.dll (6.0.6002.18909) (6.0.6002.23182) according to V3.0
  if(dllVer3 != "6.0.6002.18909" && dllVer3 != "6.0.6002.23182")
  {
    security_hole(0);
    exit(0);
  }

  ## Check for Wmv9vcm.dll version
  if(dllVer2 != "0" && version_is_less(version:dllVer2, test_version:"9.0.1.3073"))
  {
    security_hole(0);
    exit(0);
  }
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Wmvdecod.dll version
  if(dllVer3 != "0")
  {
    if(version_is_less(version:dllVer3, test_version:"6.1.7601.18220") ||
       version_in_range(version:dllVer3, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22401")){
      security_hole(0);
    }
    exit(0);
  }
}

## Win 8
else if(hotfix_check_sp(win8:1) > 0)
{
 ## Check for Wmvdecod.dll version
  if(dllVer3 != "0")
  {
    if(version_is_less(version:dllVer3, test_version:"6.2.9200.16604") ||
       version_in_range(version:dllVer3, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20707")){
      security_hole(0);
    }
    exit(0);
  }
}
