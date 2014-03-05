###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-055.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Visio Remote Code Execution Vulnerability (2560847)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
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
tag_impact = "Successful exploitation could allow users to execute arbitrary code via a
  specially crafted visio file.
  Impact Level: System";
tag_affected = "Microsoft Office Visio 2003 SP3 and prior.";
tag_insight = "The flaw exists due to the way that Microsoft Office Visio loads external
  libraries, when handling specially crafted Visio files.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/MS11-055.mspx";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS11-055.";

if(description)
{
  script_id(902455);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-13 17:31:13 +0200 (Wed, 13 Jul 2011)");
  script_cve_id("CVE-2010-3148");
  script_bugtraq_id(42681);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Visio Remote Code Execution Vulnerability (2560847)");
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
  script_summary("Check for version of vulnurable file 'Omfc.dll'");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2493523");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS11-055.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## Get Office File Path
ovPath = registry_get_sz(item:"Path",
         key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\visio.exe");

if(!ovPath){
  exit(0);
}

offPath = ovPath  - "\Visio11" + "OFFICE11";
dllVer = fetch_file_version(sysPath:offPath, file_name:"Omfc.dll");
if(!dllVer){
  exit(0);
}

## Grep for version
if(version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8331.0")){
  security_hole(0);
}
