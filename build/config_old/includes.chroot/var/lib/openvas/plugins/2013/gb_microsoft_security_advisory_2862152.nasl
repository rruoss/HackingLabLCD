###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_2862152.nasl 75 2013-11-22 14:32:56Z veerendragg $
#
# Microsoft DirectAccess Security Advisory (2862152)
#
# Authors:
# Shakeel <bhatshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804143";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 75 $");
  script_cve_id("CVE-2013-3876");
  script_bugtraq_id(63666);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-11-22 15:32:56 +0100 (Fri, 22 Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-14 14:28:18 +0530 (Thu, 14 Nov 2013)");
  script_name("Microsoft DirectAccess Security Advisory (2862152)");

  tag_summary =
"This host is missing an important security update according to Microsoft
advisory (2862152).";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to improper verification of DirectAccess server connections
to DirectAccess clients by DirectAccess.";

  tag_impact =
"Successful exploitation will allow an attacker to intercept the target user's
network traffic and potentially determine their encrypted domain credentials.";

  tag_affected =
"Microsoft Windows XP x32 Edition Service Pack 3 and prior
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Vista Edition Service Pack 1 and prior
Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows 8
Microsoft Windows Server 2012
Microsoft Windows 8.1 x32/x64";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/advisory/2862152";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/show/osvdb/99692");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/63666");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/advisory/2862152");
  script_summary("Check for the vulnerable file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
sysPath = "";
fwpuVer="";
oakleyVer="";

## check for os and service pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3, win7:2,
  win7x64:2, win2008:3, win2008x64:3, win2008r2:2, win8:1, win2012:1,
  win8_1:1, win8_1x64:1)<= 0){
    exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version
oakleyVer = fetch_file_version(sysPath, file_name:"system32\oakley.dll");
fwpuVer=fetch_file_version(sysPath, file_name:"system32\fwpuclnt.dll");

if(oakleyVer  || fwpuVer )
{
  ## Windows XP
  if(hotfix_check_sp(xp:4) > 0)
  {
    ## Grep for the file version
    if(version_is_less(version:oakleyVer, test_version:"5.1.2600.6462")){
      security_hole(0);
    }
    exit(0);
  }

  ## Windows XP Professional x64 edition and Windows Server 2003
  if(hotfix_check_sp(xpx64:3,win2003x64:3,win2003:3) > 0)
  {
    ## Grep for file version
    if(version_is_less(version:oakleyVer, test_version:"5.2.3790.5238")){
      security_hole(0);
    }
    exit(0);
  }

  ## Windows Vista and Windows Server 2008
  ## Currently not supporting for Vista and Windows Server 2008 64 bit
  if(hotfix_check_sp(winVista:3, win2008:3) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.0.6002.18960") ||
       version_in_range(version:fwpuVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23242")){
      security_hole(0);
    }
    exit(0);
  }

  ## Windows 7 and Windows Server 2008 R2
  if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.1.7601.18283") ||
       version_in_range(version:fwpuVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22478")){
      security_hole(0);
    }
    exit(0);
  }

  ## Windows 8 and Windows Server 2012
  if(hotfix_check_sp(win8:1, win2012:1) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.2.9200.16634") ||
       version_in_range(version:fwpuVer, test_version:"6.1.7601.20000", test_version2:"6.2.9200.20568")){
      security_hole(0);
    }
    exit(0);
  }

  ## Win 8.1
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
  {
    if(version_is_less(version:fwpuVer, test_version:"6.3.9600.16384")){
      security_hole(0);
    }
    exit(0);
  }
}
