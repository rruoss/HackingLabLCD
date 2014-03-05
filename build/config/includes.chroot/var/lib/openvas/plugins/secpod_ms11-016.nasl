###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-016.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Groove Remote Code Execution Vulnerability (2494047)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation allows remote attackers to execute arbitrary
  code by tricking a user into opening a file *.vcg from a network share.
  Impact Level: System/Application";
tag_affected = "Microsoft Groove 2007 Service Pack 2 and prior";
tag_insight = "The application insecurely loading certain librairies (e.g. 'mso.dll') from
  the current working directory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-016.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-016.";

if(description)
{
  script_id(902351);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-03-09 15:35:07 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2010-3146");
  script_bugtraq_id(42695);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Microsoft Groove Remote Code Execution Vulnerability (2494047)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41104/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2188");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS11-016.mspx");

  script_description(desc);
  script_summary("Check for the version of 'Groove.exe' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "secpod_office_products_version_900032.nasl");
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


include("secpod_reg.inc");
include("version_func.inc");

# MS11-016 Hotfix
if((hotfix_missing(name:"2494047") == 0)){
  exit(0);
}

## Microsoft Groove 2007
exeVer = get_kb_item("SMB/Office/Groove/Version");
if(exeVer =~ "^12\..*")
{
  # Grep for GROOVE.EXE version 12.0 < 12.0.6550.5004
  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6550.5003"))
  {
    security_hole(0);
    exit(0);
  }
}
