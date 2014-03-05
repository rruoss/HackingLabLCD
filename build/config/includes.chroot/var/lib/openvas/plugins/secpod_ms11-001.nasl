###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-001.nasl 13 2013-10-27 12:16:33Z jan $
#
# Windows Backup Manager Remote Code Execution Vulnerability (2478935)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  code and conduct DLL hijacking attacks.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista Service Pack 2 and prior.";
tag_insight = "The flaw is due to the application insecurely loading certain
  librairies from the current working directory, which could allow attackers
  to execute arbitrary code and conduct DLL hijacking attacks via a Trojan
  horse fveapi.dll which is located in the same folder as a .wbcat file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS11-001.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-001.";

if(description)
{
  script_id(901173);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-12 13:59:47 +0100 (Wed, 12 Jan 2011)");
  script_cve_id("CVE-2010-3145");
  script_bugtraq_id(42763);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Windows Backup Manager Remote Code Execution Vulnerability (2478935)");
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


  script_description(desc);
  script_summary("Check for the version of Sdclt.exe file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2478935");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/63788");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14751/");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS11-001.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3) <= 0){
  exit(0);
}

## MS11-001 Hotfix (2478935)
if(hotfix_missing(name:"2478935") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

exePath = sysPath + "\system32\Sdclt.exe";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath);

## Get Version of Sdclt.exe file
exeVer = GetVer(file:file, share:share);
if(!exeVer){
  exit(0);
}

## Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    ## Check for Sdclt.exe version
    if(version_is_less(version:exeVer, test_version:"6.0.6001.18561")){
      security_hole(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Check for Sdclt.exe version
    if(version_is_less(version:exeVer, test_version:"6.0.6002.18353")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}
