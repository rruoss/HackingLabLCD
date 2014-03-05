###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms09-036.nasl 14 2013-10-27 12:33:37Z jan $
#
# Microsoft Windows ASP.NET Denial of Service Vulnerability(970957)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to cause the application
  pool on the affected web server to become unresponsive, denying service to
  legitimate users.
  Impact Level: System/Application";
tag_affected = "Microsoft .NET Framework 3.5/SP 1
  Microsoft .NET Framework 2.0 SP 1/SP 2";
tag_insight = "The flaws is caused by caused by an error in ASP.NET when managing request
  scheduling, which could allow attackers to create specially crafted anonymous
  HTTP requests and cause the web server with ASP.NET in integrated mode to
  become non-responsive.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS09-036";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-036.";

if(description)
{
  script_id(801482);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-13 14:33:55 +0100 (Mon, 13 Dec 2010)");
  script_cve_id("CVE-2009-1536");
  script_bugtraq_id(35985);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Microsoft Windows ASP.NET Denial of Service Vulnerability(970957)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36127/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2231");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS09-036");

  script_description(desc);
  script_summary("Check for the version of System.web.dll file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3, win2008:3) <= 0){
  exit(0);
}

## Check Hotfix MS09-036
if((hotfix_missing(name:"972591") == 0) || (hotfix_missing(name:"972592") == 0)||
   (hotfix_missing(name:"972593") == 0) || (hotfix_missing(name:"972594") == 0)){
    exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    # Get the version of system.web.dll
    Ver = fetch_file_version(sysPath:path, file_name:"system.web.dll");
    if(Ver)
    {
      ## Windows Vista and 2008 Server
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        ## Check for the version system.web.dll
        if(version_in_range(version:Ver, test_version:"2.0.50727.1000", test_version2:"2.0.50727.1870") ||
           version_in_range(version:Ver, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3600"))
        {
          security_warning(0);
          exit(0);
        }
      }
    }
  }
}
