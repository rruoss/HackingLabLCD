###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-066.nasl 14 2013-10-27 12:33:37Z jan $
#
# Vulnerability in Remote Procedure Call Could Allow Remote Code Execution (982802)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright (c) 2010 SecPod, http://www.secpod.org
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code and
  take complete control of an affected system. Failed exploit attempts will
  likely result in a denial-of-service condition.
  Impact Level: System";
tag_affected = "Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2.";
tag_insight = "The flaw is due to the way that the Remote Procedure Call (RPC) client
  implementation allocates memory when parsing specially crafted RPC responses.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-066.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-066.";

if(description)
{
  script_id(902300);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2010-2567");
  script_bugtraq_id(43119);
  script_name("Vulnerability in Remote Procedure Call Could Allow Remote Code Execution (982802)");
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
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-066.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable file version Rpcrt4.dll");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3) <= 0){
  exit(0);
}
# Check Hotfix Missing 982802
if(hotfix_missing(name:"982802") == 0){
  exit(0);
}
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\Rpcrt4.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    # Grep for Rpcrt4.dll < 5.1.2600.6015
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6015")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}

# Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Rpcrt4.dll version < 5.2.3790.4750
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4750")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}
