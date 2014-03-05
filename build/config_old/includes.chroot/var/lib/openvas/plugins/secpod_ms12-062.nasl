###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-062.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft System Center Configuration Manager XSS Vulnerability (2741528)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to insert arbitrary HTML
  and script code, which will be executed in a user's browser session in the
  context of an affected site.
  Impact Level: Application";
tag_affected = "Microsoft Systems Management Server 2003 SP3 and prior
  Microsoft System Center Configuration Manager 2007 SP2 R2 or R3 and prior";
tag_insight = "Input validation error due the way System Center Configuration Manager
  handles specially crafted requests, which can be exploited to insert
  arbitrary HTML and script code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-062";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-062.";

if(description)
{
  script_id(902688);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-2536");
  script_bugtraq_id(55430);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-12 09:31:18 +0530 (Wed, 12 Sep 2012)");
  script_name("Microsoft System Center Configuration Manager XSS Vulnerability (2741528)");
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
  script_summary("Check for the vulnerable 'Reportinginstall.exe' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_system_center_configmgr_detect_win.nasl");
  script_require_keys("MS/ConfigMgr/Version", "MS/ConfigMgr/Path",
                      "MS/SMS/Version", "MS/SMS/Path");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50497");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2741528");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS12-062");
  exit(0);
}


include("version_func.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

## Variables Initialization
path = "";
oglVer = "";
attVer = "";
commVer = "";

## Check for Microsoft Microsoft System Center Configuration Manager 2007
if(get_kb_item("MS/ConfigMgr/Version"))
{
  ## Get Installed Path
  path = get_kb_item("MS/ConfigMgr/Path");
  if(path && "Could not find the install Location" >!< path)
  {
    ## Get Version from Reportinginstall.exe
    path = path - "\AdminUI";
    path = path + "\bin\i386";
    confVer = fetch_file_version(sysPath:path, file_name:"Reportinginstall.exe");
    if(confVer)
    {
      if(version_in_range(version:confVer, test_version:"4.0", test_version2:"4.0.6487.2215"))
      {
        security_warning(0);
        exit(0);
      }
    }
  }
}

## Check for Microsoft Systems Management Server 2003
if(get_kb_item("MS/SMS/Version"))
{
  ## Get Installed Path
  path = get_kb_item("MS/SMS/Path");
  if(path && "Could not find the install Location" >!< path)
  {
    ## Get Version from Reportinginstall.exe
    path = path + "\bin\i386";
    confVer = fetch_file_version(sysPath:path, file_name:"Reportinginstall.exe");
    if(confVer)
    {
      if(version_in_range(version:confVer, test_version:"2.0", test_version2:"2.50.4253.3128"))
      {
        security_warning(0);
        exit(0);
      }
    }
  }
}
