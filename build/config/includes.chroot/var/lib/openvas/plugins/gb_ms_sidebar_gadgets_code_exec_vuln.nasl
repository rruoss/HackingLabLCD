###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_sidebar_gadgets_code_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Sidebar and Gadgets Remote Code Execution Vulnerability (2719662)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code as the logged-on user.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior";
tag_insight = "Windows Sidebar when running insecure Gadgets allows an attacker to
  run arbitrary code.";
tag_solution = "Apply the Patch from below links,
  http://technet.microsoft.com/en-us/security/advisory/2719662";
tag_summary = "This host is installed with Microsoft Windows Sidebar and Gadgets
  and is prone to remote code execution vulnerability.";

if(description)
{
  script_id(802886);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-07-12 14:18:37 +0530 (Thu, 12 Jul 2012)");
  script_name("Microsoft Sidebar and Gadgets Remote Code Execution Vulnerability (2719662)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2719662");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2719662");

  script_description(desc);
  script_summary("Check for the presence of Windows Sidebar key");
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

## Variables Initialization
sidebarVal = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2) <= 0){
  exit(0);
}

## Confirm Windows Sidebar and Gadgets is Enabled before checking for patch
key1 = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\sidebar.exe";
if(registry_key_exists(key:key1))
{
  ## Check for Sidebar key
  key2 = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar";
  if(registry_key_exists(key:key2))
  {
    sidebarVal = registry_get_dword(key:key2, item:"TurnOffSidebar");
    if(!sidebarVal && !(int(sidebarVal) == 1))
    {
      security_hole(0);
      exit(0);
    }
  }
  else
  {
    security_hole(0);
    exit(0);
  }
}
