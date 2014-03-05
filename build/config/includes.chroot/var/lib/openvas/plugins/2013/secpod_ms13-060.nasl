###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-060.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft Unicode Scripts Processor Remote Code Execution Vulnerability (2850869)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "
  Impact Level: System";

if(description)
{
  script_id(902991);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3181");
  script_bugtraq_id(61697);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-14 09:22:01 +0530 (Wed, 14 Aug 2013)");
  script_name("Microsoft Unicode Scripts Processor Remote Code Execution Vulnerability (2850869)");

  tag_summary =
"This host is missing an critical security update according to
Microsoft Bulletin MS13-060.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an error within the Unicode Scripts Processor (USP10.dll)
when processing OpenType fonts.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code and or cause memory corruption.";

  tag_affected =
"Microsoft Windows XP x32/64 Edition Service Pack 3 and prior
Microsoft Windows 2003 x32/64 Edition Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-060";

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54364");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2850869");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/54364");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-060");
  script_summary("Check for the vulnerable 'USP10.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from USP10.dll file
exeVer = fetch_file_version(sysPath, file_name:"system32\USP10.dll");
if(!exeVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Grep for USP10.dll < 1.420.2600.6421
  if(version_is_less(version:exeVer, test_version:"1.420.2600.6421")){
    security_hole(0);
  }
  exit(0);
}

## Windows 2003 x86, Windows XP x64 and Windows 2003 x64
else if(hotfix_check_sp(win2003:3, xpx64:3, win2003x64:3) > 0)
{
  ## Grep for USP10.dll version < 1.422.3790.5194
  if(version_is_less(version:exeVer, test_version:"1.422.3790.5194")){
    security_hole(0);
  }
  exit(0);
}
