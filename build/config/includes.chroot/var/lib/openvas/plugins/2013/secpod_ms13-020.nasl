###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-020.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft OLE Automation Remote Code Execution Vulnerability (2802968)
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code.
  Impact Level: System";

tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior";
tag_insight = "The flaw is due to memory allocation error in Microsoft Windows Object
  Linking and Embedding (OLE) Automation, This can be exploited to execute
  arbitrary code on the target system.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-020";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS13-020.";

if(description)
{
  script_id(902942);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1313");
  script_bugtraq_id(57863);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-02-13 06:09:30 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft OLE Automation Remote Code Execution Vulnerability (2802968)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2802968");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028118");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-020");

  script_description(desc);
  script_summary("Check for the vulnerable 'Oleaut32.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
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
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Oleaut32.dll file
exeVer = fetch_file_version(sysPath, file_name:"system32\Oleaut32.dll");
if(!exeVer){
  exit(0);
}

## Windows XP
## Grep for Oleaut32.dl < 5.1.2600.6341
if(version_is_less(version:exeVer, test_version:"5.1.2600.6341")){
  security_hole(0);
}
