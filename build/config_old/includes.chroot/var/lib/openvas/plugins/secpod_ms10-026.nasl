###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-026.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft MPEG Layer-3 Codecs Remote Code Execution Vulnerability (977816)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-11-17
#      - To detect file version 'L3codeca.acm' on vista and win 2008
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to gain complete control
  of an affected system remotely. An attacker could install programs view,
  change, or delete data; or create new accounts with full user rights.
  Impact Level: System";
tag_affected = "Microsoft Windows 2000 Service Pack 4 and prior
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows 2003 Service Pack 2 and prior
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaw is due the error in 'Microsoft MPEG Layer-3 audio codecs', which
  does not properly handle specially crafted AVI files containing an MPEG
  Layer-3 audio stream.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-026.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-026.";

if(description)
{
  script_id(902038);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-04-14 17:51:53 +0200 (Wed, 14 Apr 2010)");
  script_cve_id("CVE-2010-0480");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft MPEG Layer-3 Codecs Remote Code Execution Vulnerability (977816)");
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
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS10-026.mspx");
  script_xref(name : "URL" , value : "http://www.symantec.com/connect/blogs/microsoft-patch-tuesday-april-2010");

  script_description(desc);
  script_summary("Check for the vulnerable 'L3codecx.ax' file version");
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

## This function will return the version of the given file
function get_file_version(sysPath, file_name)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                       string:sysPath + "\" + file_name);

  sysVer = GetVer(file:file, share:share);
  if(!sysVer){
    return(FALSE);
  }

  return(sysVer);
}

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# Check for MS10-026 Hotfix
if(hotfix_missing(name:"977816") == 0){
 exit(0);
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = get_file_version(sysPath, file_name:"l3codecx.ax");
  if(!sysVer){
    exit(0);
  }
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  # Grep L3codecx.ax version < 1.6.0.51
  if(version_is_less(version:sysVer, test_version:"1.6.0.51"))
  {
    security_hole(0);
    exit(0);
  }
}

## Get System32 path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(sysPath)
{ 
  sysVer = get_file_version(sysPath, file_name:"System32\L3codeca.acm");
  if(!sysVer){
    exit(0);
  }
}

## Windows Vista and 2008 Server
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  # Grep L3codeac.acm version < 1.9.0.402
  if(version_is_less(version:sysVer, test_version:"1.9.0.402")){
    security_hole(0);
  }
}

