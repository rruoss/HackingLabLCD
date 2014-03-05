###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_windows_hid_over_usb_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# MS Windows HID Functionality(Over USB) Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allows user-assisted attackers to execute
  arbitrary programs via crafted USB data.
  Impact Level: System/Application";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows XP Service Pack 2 and prior
  Microsoft Windows 2k Service Pack 4 and prior
  Microsoft Windows 2K3 Service Pack 2 and prior
  Microsoft Windows 2k8 Service Pack 4 and prior
  Microsoft Windows Vista service Pack 2 and prior";
tag_insight = "The flaw is due to error in USB divice driver, which does not properly
  warn the user before enabling additional Human Interface Device (HID)
  functionality.";
tag_solution = "No solution or patch is available as of 25th january, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/";
tag_summary = "This host is installed with USB device driver software and is prone
  to code execution vulnerability.";

if(description)
{
  script_id(801581);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_cve_id("CVE-2011-0638");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_name("MS Windows HID Functionality(Over USB) Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://www.cs.gmu.edu/~astavrou/publications.html");
  script_xref(name : "URL" , value : "http://news.cnet.com/8301-27080_3-20028919-245.html");
  script_xref(name : "URL" , value : "http://www.blackhat.com/html/bh-dc-11/bh-dc-11-briefings.html#Stavrou");

  script_description(desc);
  script_summary("Check for the existance of hidserv.dll file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
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
include("secpod_smb_func.inc");

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllPath = sysPath + "\system32\hidserv.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

## Get Version from hidserv.dll file
dllVer = GetVer(file:file, share:share);

## Check for the existance of file
if(dllVer){
  security_hole(0);
}
