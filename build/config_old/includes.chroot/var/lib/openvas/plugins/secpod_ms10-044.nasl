###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-044.nasl 14 2013-10-27 12:33:37Z jan $
#
# MS Office Access ActiveX Controls Remote Code Execution Vulnerabilities(982335)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attackers to compromise a
  vulnerable system by tricking a user into visiting a specially crafted
  web page.
  Impact Level: System/Application";
tag_affected = "Microsoft Office Access 2003/2007";
tag_insight = "The flaws are caused by a memory corruption and an uninitialized variable
  within 'ACCWIZ.dll' (Microsoft Access Wizard Controls) ActiveX control.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-044.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-044.";

if(description)
{
  script_id(902218);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-14 10:07:03 +0200 (Wed, 14 Jul 2010)");
  script_cve_id("CVE-2010-0814", "CVE-2010-1881");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("MS Office Access ActiveX Controls Remote Code Execution Vulnerabilities(982335)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1799");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms10-044.mspx");

  script_description(desc);
  script_summary("Check for the vulnerable EXE file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_keys("SMB/Office/Access/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

accVer = get_kb_item("SMB/Office/Access/Version");
if(!accVer){
  exit(0);
}

## Check for Office Access < 11.0.8321.0, 12.0.6535.5005
if(version_in_range(version:accVer, test_version:"11.0", test_version2:"11.0.8320") ||
   version_in_range(version:accVer, test_version:"12.0", test_version2:"12.0.6535.5004")){
  security_hole(0);
}
