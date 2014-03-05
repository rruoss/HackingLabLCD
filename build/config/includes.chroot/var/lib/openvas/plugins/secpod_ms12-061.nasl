###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-061.nasl 12 2013-10-27 11:15:33Z jan $
#
# MS Visual Studio Team Foundation Server Privilege Elevation Vulnerability (2719584)
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
tag_impact = "Successful exploitation could allow an attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.
  Impact Level: Application";
tag_affected = "Microsoft Visual Studio Team Foundation Server 2010 Service Pack 1";
tag_insight = "The application does not validate certain unspecified input before returning
  it to the user. This may allow a user to create a specially crafted request
  that would execute arbitrary script code in a user's browser.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-061";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-061.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903040";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 12 $");
  script_bugtraq_id(55409);
  script_cve_id("CVE-2012-1892");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-12 11:38:17 +0530 (Wed, 12 Sep 2012)");
  script_name("MS Visual Studio Team Foundation Server Privilege Elevation Vulnerability (2719584)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50463/");
  script_xref(name : "URL" , value : "http://www.osvdb.org/show/osvdb/85315");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-061");

  script_description(desc);
  script_summary("Check for the vulnerable file versions");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl",
                      "gb_ms_vs_team_foundation_server_detect.nasl");
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
include("version_func.inc");
include("secpod_smb_func.inc");

## Confirm Windows
if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## Variables Initialization
path = "";
version = "";
dllVer = "";

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Microsoft Visual Studio Team Foundation Server 2010
version = get_kb_item("MS/VS/Team/Foundation/Server/Ver");
if(version && (version =~ "^10\..*"))
{
  path = sysPath + "\assembly\GAC_MSIL\Microsoft.TeamFoundation.WebAccess\10.0.0.0__b03f5f7f11d50a3a";
  if(path)
  {
    ## Get Microsoft.TeamFoundation.WebAccess.dll file version
    dllVer = fetch_file_version(sysPath:path, file_name:"Microsoft.TeamFoundation.WebAccess.dll");
    if(dllVer)
    {
      ## Check for Microsoft.TeamFoundation.WebAccess.dll version
      if(version_is_less(version:dllVer, test_version:"10.0.40219.417")){
        security_warning(0);
      }
    }
  }
}
