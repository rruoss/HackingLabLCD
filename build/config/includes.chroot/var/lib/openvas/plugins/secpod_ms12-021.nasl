###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-021.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Visual Studio Privilege Elevation Vulnerability (2651019)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow attacker to execute arbitrary code with
  elevated privileges.
  Impact Level: System/Application";
tag_affected = "Microsoft Visual Studio 2008 SP 1 and prior
  Microsoft Visual Studio 2010 SP 1 and prior";
tag_insight = "The flaw is due to the application loading add-ins from insecure paths.
  This can be exploited to gain additional privileges by placing malicious add-
  ins in certain directories and tricking a user into starting Visual Studio.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-021";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-021.";

if(description)
{
  script_id(902817);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0008");
  script_bugtraq_id(52329);
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-14 10:10:10 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Visual Studio Privilege Elevation Vulnerability (2651019)");
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


  script_description(desc);
  script_summary("Check for the version of 'Vsaenv.exe' and 'AppenvStub.dll' files");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_visual_prdts_detect.nasl");
  script_require_keys("Microsoft/VisualStudio/Ver");
  script_require_ports(139, 445);
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48396");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2669970");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2645410");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2645410");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026792");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-021");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
vsPath = "";
vsVer = NULL;
dllVer = NULL;
exeVer = NULL;

## MS12-021 Hotfix check
if((hotfix_missing(name:"2669970") == 0) && (hotfix_missing(name:"2644980") == 0) &&
   (hotfix_missing(name:"2645410") == 0)){
  exit(0);
}

## Get Visual Studio Version
vsVer = get_kb_item("Microsoft/VisualStudio/Ver");
if(!vsVer){
  exit(0);
}

## Check for Visual Studio 2008 SP1
if(vsVer =~ "^9\..*")
{
  vsPath = registry_get_sz(key:"SOFTWARE\Microsoft\VSA\9.0", item:"InstallDir");
  if(!vsPath){
    exit(0);
  }

  ## Get Vsaenv.exe Version
  exeVer = fetch_file_version(sysPath:vsPath, file_name:"Vsaenv.exe");

  ## Check for Vsaenv.exe version < 9.0.30729.5797
  if(exeVer && version_is_less(version:exeVer, test_version:"9.0.30729.5797"))
  {
    security_hole(0);
    exit(0);
  }
}

## Check for Visual Studio 2010/2010 SP1
if(vsVer =~ "^10\..*")
{
  ## Get Visual Studio Path
  vsPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\10.0", item:"InstallDir");
  if(!vsPath){
    exit(0);
  }

  ## Get AppenvStub.dll Version
  dllVer = fetch_file_version(sysPath:vsPath, file_name:"ShellExtensions\Platform\AppenvStub.dll");

  ## Check for Visual Studio 2010 version 10 < 10.0.30319.552
  ## Visual Studio 2010 SP1 version 10 < 10.0.40219.377
  if(dllVer && (version_is_less(version:dllVer, test_version:"10.0.30319.552") ||
     version_in_range(version:dllVer, test_version:"10.0.40000.000", test_version2:"10.0.40219.376"))){
    security_hole(0);
  }
}
