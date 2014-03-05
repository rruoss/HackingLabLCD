###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-046.nasl 16 2013-10-27 13:09:52Z jan $
#
# Microsoft Windows Image Color Management System Code Execution Vulnerability (952954)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful exploitation could execute arbitrary code when a user opens a
  specially crafted image file and can gain same user rights as the local
  user. An attacker could then install programs; view, change, or delete
  data, or create new accounts.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K/XP/2003";
tag_insight = "The flaw is due to the way Microsoft Color Management System (MSCMS)
  module of the Microsoft ICM component handles memory allocation.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms08-049.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-046.";


if(description)
{
  script_id(800023);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-07 16:11:33 +0200 (Tue, 07 Oct 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2008-2245");
  script_bugtraq_id(30594);
  script_name("Microsoft Windows Image Color Management System Code Execution Vulnerability (952954)");
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
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-046.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable File Version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
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

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

function get_version()
{
  dllPath = registry_get_sz(item:"Install Path",
                           key:"SOFTWARE\Microsoft\COM3\Setup");
  if(!dllPath){
    exit(0);
  }
  dllPath += "\Mscms.dll";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

  soc = open_sock_tcp(port);
  if(!soc){
    exit(0);
  }

  r = smb_session_request(soc:soc, remote:name);
  if(!r)
  {
    close(soc);
    exit(0);
  }
  prot = smb_neg_prot(soc:soc);
  if(!prot)
  {
    close(soc);
    exit(0);
  }

  r = smb_session_setup(soc:soc, login:login, password:pass,
                        domain:domain, prot:prot);
  if(!r)
  {
    close(soc);
    exit(0);
  }

  uid = session_extract_uid(reply:r);

  r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
  tid = tconx_extract_tid(reply:r);
  if(!tid)
  {
    close(soc);
    exit(0);
  }

  fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
  if(!fid)
  {
    close(soc);
    exit(0);
  }

  v = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, offset:60000,
                 verstr:"prod");
  close(soc);
  return v;
}

# Check for MS08-046 Hotfix (952954)
if(hotfix_missing(name:"952954") == 0){
  exit(0);
}

fileVer = get_version();
if(!fileVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  # Check for version < 5.0.2195.7162
  if(version_is_less(version:fileVer, test_version:"5.0.2195.7162")){
    security_hole(0);
  }
  exit(0);
}
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # < 5.1.2600.3396
    if(version_is_less(version:fileVer, test_version:"5.1.2600.3396")){
      security_hole(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Check for version < 5.1.2600.5627
    if(version_is_less(version:fileVer, test_version:"5.1.2600.5627")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Check for version < 5.2.3790.3163
    if(version_is_less(version:fileVer, test_version:"5.2.3790.3163")){
      security_hole(0);
    }
    exit(0);
  }
  else if("Service Pack 2" >< SP)
  {
    # Check for version < 5.2.3790.4320
    if(version_is_less(version:fileVer, test_version:"5.2.3790.4320")){
      security_hole(0);
    }
    exit(0);
  }
  security_hole(0);
}
