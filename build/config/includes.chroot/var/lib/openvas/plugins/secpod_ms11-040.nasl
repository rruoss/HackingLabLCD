###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-040.nasl 13 2013-10-27 12:16:33Z jan $
#
# MS Windows Threat Management Gateway Firewall Client Remote Code Execution Vulnerability (2520426)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the application. Failed exploit attempts will result
  in denial-of-service conditions.
  Impact Level: System/Application";
tag_affected = "Microsoft Forefront Threat Management Gateway 2010 SP1 and prior.";
tag_insight = "The flaw is due to error when setting proper bounds to the
  'NSPLookupServiceNext()' function, that allow remote code execution if an
  attacker leveraged a client computer to make specific requests on a system
  where the TMG firewall client is used.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-040.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-040.";

if(description)
{
  script_id(902444);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-06-15 15:55:00 +0200 (Wed, 15 Jun 2011)");
  script_cve_id("CVE-2011-1889");
  script_bugtraq_id(48181);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("MS Windows Threat Management Gateway Firewall Client Remote Code Execution Vulnerability (2520426");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2520426");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS11-040.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable 'Fwcmgmt.exe' file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "smb_registry_access.nasl");
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

## MS11-040 Hotfix (2520426)
if(hotfix_missing(name:"2520426") == 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\";

if(!registry_key_exists(key:key)) {
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  sysPath = registry_get_sz(key:key + item, item:"InstallRoot");
  if("Forefront TMG Client" >< sysPath)
  {
    ## Get Version from Fwcmgmt.exe
    dllVer = fetch_file_version(sysPath, file_name:"Fwcmgmt.exe");
    if(!dllVer){
      exit(0);
    }
    if(version_is_less(version:dllVer, test_version:"7.0.7734.182"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
