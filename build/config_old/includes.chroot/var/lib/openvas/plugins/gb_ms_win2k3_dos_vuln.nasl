###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_win2k3_dos_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Windows Server 2003 win32k.sys DoS Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attakers to cause denial of service by
  crashing the operating system.
  Impact Level: System";
tag_affected = "Microsoft Windows 2003 Service Pack 2 and prior.";
tag_insight = "The vulnerability lies in win32k.sys file and can be exploited via vectors
  related to CreateWindow, TranslateMessage and DispatchMessage functions to
  cause a race condition between threads.";
tag_solution = "No solution or patch is available as of 4th June, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.microsoft.com/en/us/default.aspx";
tag_summary = "This host is running Windows Server 2003 operating system and is
  prone to Denial of Service vulnerability.";

if(description)
{
  script_id(800577);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-6819");
  script_bugtraq_id(35121);
  script_name("Microsoft Windows Server 2003 win32k.sys DoS Vulnerability");
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
  script_xref(name : "URL" , value : "http://downloads.securityfocus.com/vulnerabilities/exploits/35121.c");

  script_description(desc);
  script_summary("Check for the vulnerable File Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2003:3) <= 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Win32k.sys");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

SP = get_kb_item("SMB/Win2003/ServicePack");
if("Service Pack 1" >< SP)
{
  # Grep for Win32k.sys version < 5.2.3790.3291
  if(version_is_less_equal(version:sysVer, test_version:"5.2.3790.3291")){
    security_warning(0);
 }
}

else if("Service Pack 2" >< SP)
{
  # Grep for Win32k.sys version < 5.2.3790.4456
  if(version_is_less_equal(version:sysVer, test_version:"5.2.3790.4456")){
    security_warning(0);
  }
}
