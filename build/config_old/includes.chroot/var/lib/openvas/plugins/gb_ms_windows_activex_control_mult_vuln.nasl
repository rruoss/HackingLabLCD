###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_activex_control_mult_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Windows ActiveX Control Multiple Vulnerabilities (2647518)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_solution = "Apply the patch from below link,
  http://support.microsoft.com/kb/2647518

  Workaround:
  Set the killbit for the following CLSIDs,
  {6e84d662-9599-11d2-9367-20cc03c10627},
  {7e00a3b0-8f5c-11d2-baa4-04f205c10000},
  {4ba9089c-ddfc-4206-b937-74484b06d305},
  {A3CD4BF9-EC17-47A4-833C-50A324D6FF35},
  {57733FF6-E100-4A4B-A7D1-A85AD17ABC54},
  {9B8E377B-7291-491A-B611-BB3E1D5F99F0},
  {ee5e14b0-4abf-409e-9c39-74f3d35bd85a},
  {b34b19f4-7ebe-46cb-807c-746e72ebb4b6},
  {7a7b986c-31e9-4286-88ca-b9dc481ca989},
  {8290cb76-9f61-458b-ad2c-3f6fd2e8cd7d},
  {dd7b057d-9020-4630-baf8-7a0cda04588d},
  {fc7F9cc6-e049-4698-8a25-59ad87c7dce2}.";

tag_impact = "Successful exploitation will let the remote attackers execute arbitrary code,
  and can compromise a vulnerable system.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7 Service Pack 1 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaws are due to errors in the handling of Biostat SamplePower,
  Blueberry Software Flashback Component and HP Photo Creative ActiveX
  controls.";
tag_summary = "This script will list all the vulnerable activex controls installed
  on the remote windows machine with references and cause.";

if(description)
{
  script_id(802426);
  script_version("$Revision: 12 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-14 13:25:40 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Windows ActiveX Control Multiple Vulnerabilities (2647518)");
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

  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2647518");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2647518");

  script_description(desc);
  script_summary("Check for the CLSID and Hotfix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("secpod_activex.inc");

## Confirm windows platform
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

# Hotfix check 2647518
if(hotfix_missing(name:"2647518") == 0){
  exit(0);
}

# Check if Kill-Bit is set for ActiveX control
clsids = make_list("{6e84d662-9599-11d2-9367-20cc03c10627}",
                   "{7e00a3b0-8f5c-11d2-baa4-04f205c10000}",
                   "{4ba9089c-ddfc-4206-b937-74484b06d305}",
                   "{A3CD4BF9-EC17-47A4-833C-50A324D6FF35}",
                   "{57733FF6-E100-4A4B-A7D1-A85AD17ABC54}",
                   "{9B8E377B-7291-491A-B611-BB3E1D5F99F0}",
                   "{ee5e14b0-4abf-409e-9c39-74f3d35bd85a}",
                   "{b34b19f4-7ebe-46cb-807c-746e72ebb4b6}",
                   "{7a7b986c-31e9-4286-88ca-b9dc481ca989}",
                   "{8290cb76-9f61-458b-ad2c-3f6fd2e8cd7d}",
                   "{dd7b057d-9020-4630-baf8-7a0cda04588d}",
                   "{fc7F9cc6-e049-4698-8a25-59ad87c7dce2}");

## check for each bit
foreach clsid (clsids)
{
  if(is_killbit_set(clsid:clsid) == 0)
  {
    security_hole(0);
    exit(0);
  }
}
