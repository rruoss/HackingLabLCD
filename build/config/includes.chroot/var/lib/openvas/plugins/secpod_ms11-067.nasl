###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-067.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Report Viewer Information Disclosure Vulnerability (2578230)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Microsoft Visual Studio 2005 Service Pack 1
  Microsoft Report Viewer 2005 Service Pack 1 Re-distributable Package";
tag_insight = "A flaw is due to an unspecified input passed to the Microsoft Report
  Viewer Control is not properly sanitised before being returned to the user.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link.
  http://www.microsoft.com/technet/security/bulletin/ms11-067.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-067.";

if(description)
{
  script_id(900299);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-11 06:41:03 +0200 (Thu, 11 Aug 2011)");
  script_bugtraq_id(49033);
  script_cve_id("CVE-2011-1976");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft Report Viewer Information Disclosure Vulnerability (2578230)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45514");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2548826");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2579115");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms11-067.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable Report Viewer Versions");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for Visual Studio 2005 SP1
if(egrep(pattern:"^8\..*", string:get_kb_item("Microsoft/VisualStudio/Ver")))
{
  ## MS11-067 Hotfix check
  if((hotfix_missing(name:"2548826") == 1))
  {
    ## Get Visual Studio 2005 Path
    studioPath = registry_get_sz(key:"SOFTWARE\Microsoft\VisualStudio\8.0",
                                 item:"InstallDir");
    if(studioPath){
      ## Construct complete path and get version
      reportViewPath = studioPath - "\Common7\IDE\" + "\ReportViewer";
      sysVer = fetch_file_version(sysPath:reportViewPath,
               file_name:"Microsoft.ReportViewer.WebForms.dll");

      if(sysVer)
      {
        ## Check version range from 8.0 <= 8.0.50727.5677
        if(version_in_range(version:sysVer, test_version:"8.0", test_version2:"8.0.50727.5676")){
          security_warning(0);
        }
      }
    }
  }
}

## Check Microsoft Report Viewer 2005 Service Pack 1 Re-distributable Package
## Check Microsoft Report Viewer Installed or not
key = "SOFTWARE\Microsoft\ReportViewer";
if(!registry_key_exists(key:key)){
  exit(0);
}

## MS11-067 Hotfix check
if((hotfix_missing(name:"2579115") == 0)){
  exit(0);
}

## Get the path for Microsoft Report Viewer 2005
key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Get Microsoft Report Viewer Installed Path
foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    ## Construct complete path and get version
    reportViewPath =  path + "\Microsoft Report Viewer Redistributable 2005";
    sysVer = fetch_file_version(sysPath:reportViewPath,
             file_name:"Install.res.1025.dll");

    if(sysVer)
    {
      ## Check version range from 8.0 <= 8.0.50727.5677
      if(version_in_range(version:sysVer, test_version:"8.0.50727", test_version2:"8.0.50727.5676"))
      {
        security_warning(0);
        exit(0);
      }
    }
  }
}
