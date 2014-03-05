###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-057.nasl 15 2013-10-27 12:49:54Z jan $
#
# Microsoft Windows Indexing Service ActiveX Vulnerability (969059)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow remote attackers to crash an affected
  browser or execute arbitrary code on the victim's system.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K  Service Pack 4 and prior.
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.";
tag_insight = "This issue is caused by a memory corruption error in the 'Query.dll' ActiveX
  component (included with the Indexing service) that does not properly handle
  specially crafted Web content.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms09-057.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-057.";

if(description)
{
  script_id(900881);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-15 15:35:39 +0200 (Thu, 15 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2507");
  script_bugtraq_id(36629);
  script_name("Microsoft Windows Indexing Service ActiveX Vulnerability (969059)");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/969059");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2892");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/MS09-057.mspx");

  script_description(desc);
  script_summary("Check for the version of Query.dll file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# MS09-057 Hotfix check
if(hotfix_missing(name:"969059") == 0){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\Query.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Query.dll version < 5.0.2195.7320
  if(version_is_less(version:dllVer, test_version:"5.0.2195.7320")){
    security_hole(0);
  }
}

# Windows XP
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Query.dll < 5.1.2600.3602
    if(version_is_less(version:dllVer, test_version:"5.1.2600.3602")){
      security_hole(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Query.dll < 5.1.2600.5847
    if(version_is_less(version:dllVer, test_version:"5.1.2600.5847")){
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
    # Grep for Query.dll version < 5.2.3790.4554
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4554")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}
