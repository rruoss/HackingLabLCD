###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-064.nasl 31155 2013-08-14 14:18:13Z aug$
#
# Microsoft Windows NAT Driver Denial of Service Vulnerability (2849568)
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
  script_id(902989);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3182");
  script_bugtraq_id(61685);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-08-14 08:17:31 +0530 (Wed, 14 Aug 2013)");
  script_name("Microsoft Windows NAT Driver Denial of Service Vulnerability (2849568)");

  tag_summary =
"This host is missing a important security update according to
Microsoft Bulletin MS13-064.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to an error within the Windows NAT Driver when handling ICMP
packets.";

  tag_impact =
"Successful exploitation will allow the remote attackers to cause a denial
of service.";

  tag_affected =
"Microsoft Windows Server 2012";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-064";

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54420");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2849568");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-064");
  script_summary("Check for the vulnerable 'Winnat.sys file version");
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

## Variables Initialization
sysPath = "";
WinnatVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Winnat.sys file
WinnatVer = fetch_file_version(sysPath, file_name:"system32\drivers\Winnat.sys");
if(!WinnatVer){
  exit(0);
}

if(hotfix_check_sp(win2012:1) > 0)
{
 ## Check for Winnat.sys version
  if(version_is_less(version:WinnatVer, test_version:"6.2.9200.16654") ||
     version_in_range(version:WinnatVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20761")){
    security_hole(0);
  }
  exit(0);
}
