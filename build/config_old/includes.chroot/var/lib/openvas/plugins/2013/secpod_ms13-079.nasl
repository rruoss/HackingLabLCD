###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-079.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft Windows Active Directory Denial of Service Vulnerability (2853587)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

if(description)
{
  script_id(901222);
  script_version("$Revision: 11 $");
  script_bugtraq_id(62184);
  script_cve_id("CVE-2013-3868");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-11 12:41:50 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft Windows Active Directory Denial of Service Vulnerability (2853587)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS13-079.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is caused when the LDAP directory service fails to properly handle
a specially crafted LDAP query.";

  tag_impact =
"Successful exploitation will allow attackers to crash the service.

Impact Level: Application";

  tag_affected =
"Active Directory Lightweight Directory Service (AD LDS) on,
 - Microsoft Windows 8
 - Microsoft Windows Server 2012
 - Microsoft Windows 7 x32/x64 Service Pack 1 and prior
 - Microsoft Windows Vista x32/x64 Service Pack 2 and prior
 - Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior
 - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-079";

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
  script_xref(name : "URL" , value : "http://osvdb.org/97114");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54750");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2853587");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-079");
  script_summary("Check for the vulnerable 'Ntdsatq.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
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
sysPath = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3,
                   win2008r2:2, win8:1, win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Confirm Adcive Directory is insalled or not
if(!(registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\NTDS"))){
  exit(0);
}

## Get Version from Ntdsatq.dll file
sysVer = fetch_file_version(sysPath, file_name:"system32\Ntdsatq.dll");
if(!sysVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Ntdsatq.dll version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18882") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.23154")){
    security_warning(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Ntdsatq.dll version
  if(version_is_less(version:sysVer, test_version:"6.1.7601.18219") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22399")){
    security_warning(0);
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
 ## Check for Ntdsatq.dll version
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16664") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20771")){
    security_warning(0);
  }
  exit(0);
}
