##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-059_900049.nasl 16 2013-10-27 13:09:52Z jan $
# Description: Host Integration Server RPC Service Remote Code Execution Vulnerability (956695)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

include("revisions-lib.inc");
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-059.mspx";

tag_impact = "Successful exploitation could allow local attackers to bypass the
  authentication mechanism and can access administrative functionalities via
  a specially crafted RPC request.
  Impact Level: System";
tag_affected = "Microsoft Host Integration Server 2000/2004/2006 (Server) on Windows.
  Microsoft Host Integration Server 2000/2004 (Client) on Windows.";
tag_insight = "The issue is due to an error in the SNA Remote Procedure Call (RPC) service.";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS08-059.";


if(description)
{
  script_id(900049);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(31620);
  script_cve_id("CVE-2008-3466");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Host Integration Server RPC Service Remote Code Execution Vulnerability (956695)");
  script_summary("Check for Hotfix and version of Host Integration Server");
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
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-059.mspx");
  script_description(desc);
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
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
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Host Integration Server")){
  exit(0);
}

if(hotfix_missing(name:"956695") == 0){
  exit(0);
}

hisPath = registry_get_sz(item:"Path",
          key:"SOFTWARE\Microsoft\Host Integration Server\ConfigFramework");
if(!hisPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:hisPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:hisPath + "system\Snarpcsv.exe");

hisVer = GetVer(file:file, share:share);
# Grep Snarpcsv.exe version < 7.0.2900.0
if(ereg(pattern:"^7\.0\.([01]?[0-9]?[0-9]?[0-9]|2[0-8][0-9][0-9])\.0$",
        string:hisVer)){
   security_hole(0);
}
