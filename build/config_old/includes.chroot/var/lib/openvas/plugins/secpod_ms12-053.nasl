###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-053.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Remote Desktop Protocol Remote Code Execution Vulnerability (2723135)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_affected = "Microsoft Windows XP x32 Edition Service Pack 3 and prior";
tag_insight = "The flaw is due to an error within Remote Desktop Services when
  accessing an object in memory after it has been deleted. This can be
  exploited by sending a sequence of specially crafted RDP packets to the
  target system.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-053";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-053.";

if(description)
{
  script_id(902922);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2526");
  script_bugtraq_id(54935);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-08-15 10:45:43 +0530 (Wed, 15 Aug 2012)");
  script_name("Microsoft Remote Desktop Protocol Remote Code Execution Vulnerability (2723135)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50244/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2723135");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/50244");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-053");

  script_description(desc);
  script_summary("Check for the vulnerable 'Rdpwd.sys' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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
rdpVer = "";
dkey = "";
dValue = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4) <= 0){
  exit(0);
}

## Check the RDP enable
dkey = registry_key_exists(key:"SYSTEM\CurrentControlSet\Control\Terminal Server");
if(!dkey){
  exit(0);
}

##  Exit if RDP is not enabled
dValue = registry_get_dword(key:dkey, item:"fDenyTSConnections");
if(dValue && (int(dValue) == 1)){
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
  # Check for Rdpwd.sys version < 5.1.2600.6258
  if(version_is_less(version:rdpVer, test_version:"5.1.2600.6258")){
     security_hole(0);
  }
}
