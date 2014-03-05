###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-023.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Office Remote Code Execution Vulnerabilites (2489293)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a Word file from a network share or via a malicious
  Office document.
  Impact Level: System/Application";
tag_affected = "Microsoft Office XP Service Pack 3
  Microsoft Office 2003 Service Pack 3
  Microsoft Office 2007 Service Pack 2";
tag_insight = "The flaws are caused by,
  - an error in a shared component that incorrectly restricts the path used for
    loading external libraries.
  - an error when dereferencing data structures within Office files containing
    graphic objects.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS11-023.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-023.";

if(description)
{
  script_id(902364);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2011-0107", "CVE-2011-0977");
  script_bugtraq_id(47246, 46227);
  script_name("Microsoft Office Remote Code Execution Vulnerabilites (2489293)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44015/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0942");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS11-023.mspx");

  script_description(desc);
  script_summary("Check for the version of Mso.dll file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
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

## MS Office XP, 2003, 2007
if(get_kb_item("MS/Office/Ver") =~ "^[10|11|12].*")
{
  ## Get Office File Path
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                            item:"CommonFilesDir");
  if(!path) {
    exit(0);
  }

  foreach ver (make_list("OFFICE10", "OFFICE11", "OFFICE12"))
  {
    offPath = path + "\Microsoft Shared\" + ver;
    dllVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
    if(dllVer)
    {
      ## Grep for Mso.dll versions
      if(version_in_range(version:dllVer, test_version:"10.0", test_version2:"10.0.6869.9") ||
         version_in_range(version:dllVer, test_version:"11.0", test_version2:"11.0.8332.9") ||
         version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6554.5000"))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}
