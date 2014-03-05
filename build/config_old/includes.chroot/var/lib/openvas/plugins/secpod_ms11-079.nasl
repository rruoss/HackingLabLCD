###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-079.nasl 12 2013-10-27 11:15:33Z jan $
#
# MS Forefront Unified Access Gateway Remote Code Execution Vulnerabilities (2544641)
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
tag_impact = "Successful exploitation could allow attackers to conduct cross-site scripting
  and HTTP response splitting attacks, cause a denial of service.
  Impact Level: Application";
tag_affected = "Microsoft Forefront Unified Access Gateway 2010
  Microsoft Forefront Unified Access Gateway 2010 Update 1
  Microsoft Forefront Unified Access Gateway 2010 Update 2
  Microsoft Forefront Unified Access Gateway 2010 Service Pack 1";
tag_insight = "The flaws are due to,
  - when Forefront Unified Access Gateway (UAG) does not properly handle
    script contained in a specially crafted request, allowing for malicious
    content to be reflected back to the user.
  - by an error within the MicrosoftClient.jar Java applet insecurely
    implements certain methods.
  - by improper validation of a NULL value contained within the session cookie.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-079";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-079.";

if(description)
{
  script_id(903045);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-1895", "CVE-2011-1896", "CVE-2011-1897", "CVE-2011-1969",
                "CVE-2011-2012");
  script_bugtraq_id(49979, 49972, 49974, 49983, 49980);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-26 17:47:08 +0530 (Fri, 26 Oct 2012)");
  script_name("MS Forefront Unified Access Gateway Remote Code Execution Vulnerabilities (2544641)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46402/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2522482");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2522483");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2522484");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2522485");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-079");

  script_description(desc);
  script_summary("Check for the version of vulnerable 'Whlfilter' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_forefront_unified_access_gateway_detect.nasl");
  script_require_keys("MS/Forefront/UAG/Ver");
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

## Variable Initialization
dllVer = "";
uagVer = "";
path = "";

## Get the version from KB to confirm application is installed
uagVer = get_kb_item("MS/Forefront/UAG/Ver");
if(!uagVer){
  exit(0);
}

## Get Program Files Path
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"ProgramFilesDir");
if(!path){
  exit(0);
}

## Get the Whlfilter.dll file version
dllVer = fetch_file_version(sysPath:path,
         file_name:"Microsoft Forefront Unified Access Gateway\von\bin\Whlfilter.dll");
if(!dllVer){
  exit(0);
}

## Checking for Whlfilter.dll file version
if(version_in_range(version:dllVer, test_version:"4.0.1101.0", test_version2:"4.0.1101.62") ||
   version_in_range(version:dllVer, test_version:"4.0.1152.100", test_version2:"4.0.1152.162") ||
   version_in_range(version:dllVer, test_version:"4.0.1269.200", test_version2:"4.0.1269.283") ||
   version_in_range(version:dllVer, test_version:"4.0.1752.10000", test_version2:"4.0.1752.10072")){
  security_hole(0);
}
