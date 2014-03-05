###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-022.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Expression Design Remote Code Execution Vulnerability (2651018)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code on the target system.
  Impact Level: System/Application";
tag_affected = "Microsoft Expression Design
  Microsoft Expression Design 2
  Microsoft Expression Design 3
  Microsoft Expression Design 4
  Microsoft Expression Design Service Pack 1";
tag_insight = "The flaw is due to the way that Microsoft Expression Design handles
  the loading of DLL files. An attacker can exploit this vulnerability to
  install programs, view, change, or delete data, or create new accounts with
  full user rights.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-022";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-022.";

if(description)
{
  script_id(903000);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0016");
  script_bugtraq_id(52375);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-14 10:53:40 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Expression Design Remote Code Execution Vulnerability (2651018)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48353/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026791");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-022");

  script_description(desc);
  script_summary("Check for the vulnerable 'GraphicsCore.dll' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_expression_design_detect.nasl");
  script_require_keys("MS/Expression/Design/Ver", "MS/Expression/Install/Path");
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


function version_check(ver)
{
  if(version_is_equal(version:ver, test_version:"4.0.2712.0") ||
     version_is_equal(version:ver, test_version:"4.0.2920.0")||
     version_is_equal(version:ver, test_version:"5.0.1379.0")||
     version_is_equal(version:ver, test_version:"6.0.1739.0")||
     version_is_equal(version:ver, test_version:"7.0.20516.0"))
  {
    security_hole(0);
    exit(0);
  }
}

## Variables Initialization
desinVer = "";
path = "";
dllPath = "";
dllVer = "";
ver = "";

## Get the KB
desinVer = get_kb_item("MS/Expression/Design/Ver");

## Get the installed path
path = get_kb_item("MS/Expression/Install/Path");
if(!path){
  exit(0);
}

if(desinVer && (desinVer =~ "^[4|5]\.*"))
{
  ## For diff versions of MS Expression Design and MS Expression Design 2
  foreach ver (make_list("1.0", "2"))
  {
    dllPath = path + "Design" + " " + ver;

    ## Get the version of GraphicsCore.dll file
    dllVer = fetch_file_version(sysPath:dllPath, file_name:"GraphicsCore.dll");
    if(!dllVer){
      continue;
    }
    version_check(ver:dllVer);
  }
}

## Get the version of GraphicsCore.dll file
dllVer = fetch_file_version(sysPath:path, file_name:"GraphicsCore.dll");
if(dllVer){
  version_check(ver:dllVer);
}
