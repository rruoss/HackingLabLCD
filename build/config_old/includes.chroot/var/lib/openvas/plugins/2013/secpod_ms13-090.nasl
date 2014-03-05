###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-090.nasl 64 2013-11-13 15:57:06Z veerendragg $
#
# Microsoft Windows ActiveX Control RCE Vulnerability (2900986)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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
  script_id(901225);
  script_version("$Revision: 64 $");
  script_cve_id("CVE-2013-3918");
  script_bugtraq_id(63631);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-11-13 16:57:06 +0100 (Mi, 13. Nov 2013) $");
  script_tag(name:"creation_date", value:"2013-11-13 12:27:27 +0530 (Wed, 13 Nov 2013)");
  script_name("Microsoft Windows ActiveX Control RCE Vulnerability (2900986)");

  tag_summary =
"This host is missing a critical security update according to
Microsoft Bulletin MS13-090.";

  tag_vuldetect =
"Get the ActiveX control (CLSID) information from registry and check
appropriate patch is applied or not.";

  tag_insight =
"Flaw in the InformationCardSigninHelper Class ActiveX control (icardie.dll)
and can be exploited to corrupt the system state.";

  tag_impact =
"Successful exploitation allows execution of arbitrary code when viewing a
specially crafted web page using Internet Explorer.

Impact Level: System/Application";

  tag_affected =
"Microsoft Windows 8
Microsoft Windows Server 2012
Microsoft Windows 8.1 x32/x64 Edition
Microsoft Windows XP x32 Edition Service Pack 3 and prior
Microsoft Windows XP x64 Edition Service Pack 2 and prior
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-090";

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
  script_xref(name : "URL" , value : "http://osvdb.org/99555");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55611");
  script_xref(name : "URL" , value : "http://www.zdnet.com/microsoft-to-patch-zero-day-bug-tuesday-7000023066/");
  script_xref(name : "URL" , value : "http://www.fireeye.com/blog/uncategorized/2013/11/new-ie-zero-day-found-in-watering-hole-attack.html");
  script_xref(name : "URL" , value : "http://blogs.technet.com/b/msrc/archive/2013/11/11/activex-control-issue-being-addressed-in-update-tuesday.aspx");
  script_summary("Check for the CLSID and Patch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

## Variables Initialization
clsids = "";

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, winVista:3,
   win7:2, win7x64:2, win2008:3, win2008r2:2, win2012:1, win8:1,
   win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}


## CLSID List
clsids = make_list(
  "{19916e01-b44e-4e31-94a4-4696df46157b}",
  "{c2c4f00a-720e-4389-aeb9-e9c4b0d93c6f}",
  "{53001f3a-f5e1-4b90-9c9f-00e09b53c5f1}"
);

## Updated secpod_activex.inc to check for 67109888
## i.e 0x400 == 1024 and 0x4000400 == 67109888
## in the workaround also they have to set it as dword:04000400 == 67109888
## After applying the patch also killbit regisrty value is 0x4000400 == 67109888

foreach clsid (clsids)
{
  ## Check if Kill-Bit is set for ActiveX control
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_hole(0);
    exit(0);
  }
}
