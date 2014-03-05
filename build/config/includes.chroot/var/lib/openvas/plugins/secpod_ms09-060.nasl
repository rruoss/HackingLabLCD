###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-060.nasl 15 2013-10-27 12:49:54Z jan $
#
# MS ATL ActiveX Controls for MS Office Could Allow Remote Code Execution (973965)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-03-23
# Removed the 'hotfix_missing()' function
#
# Updated By: Rachana Shetty <srachana@secpod.com> on 2012-05-28
# Added get_kb_item for application confirmation of Visio Viewer
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  code with SYSTEM privileges, and can cause Denial of Service.
  Impact Level: System/Application";
tag_affected = "Microsoft Office Outlook 2002/2003/2007
  Microsoft Office Visio Viewer 2007";
tag_insight = "Multiple flaws are due to
  - Error in the Microsoft Active Template Library (ATL) within the ATL headers
    that handle instantiation of an object from data streams.
  - Error in the ATL headers, which could allow a string to be read with no ending
    NULL bytes, which could allow an attacker to manipulate a string to read extra
    data beyond the end of the string and thus disclose information in memory.
  - Error in the Microsoft Active Template Library (ATL) headers, which could allow
    attackers to call 'VariantClear()' on a variant that has not been correctly
    initialized, leading to arbitrary code execution.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms09-060";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-060.";

if(description)
{
  script_id(901040);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-10-14 16:47:08 +0200 (Wed, 14 Oct 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0901", "CVE-2009-2493","CVE-2009-2495");
  script_bugtraq_id(35828, 35830, 35832);
  script_name("MS ATL ActiveX Controls for MS Office Could Allow Remote Code Execution (973965)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/2895");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms09-060");

  script_description(desc);
  script_summary("Check for the vulnerable DLL file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/Office/Outlook/Version", "SMB/Office/VisioViewer/Ver");
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

visVer = get_kb_item("SMB/Office/Outloook/Version");
if(visVer)
{
  #Check for Office OutLook  < 10.0.6856.0 ,11.0.8312.0, 12.0.6514.5000
  if(version_in_range(version:visVer, test_version:"10.0", test_version2:"10.0.6855") ||
     version_in_range(version:visVer, test_version:"11.0", test_version2:"11.0.8311") ||
     version_in_range(version:visVer, test_version:"12.0", test_version2:"12.0.6514.4999"))
  {
    security_hole(0);
    exit(0);
  }
}

visioVer = get_kb_item("SMB/Office/VisioViewer/Ver");
if(visioVer)
{
  #Check for Microsoft Office Visio Viewer < 12.0.6513.5000
  if(version_in_range(version:visioVer, test_version:"12.0", test_version2:"12.0.6513.4999")){
     security_hole(0);
  }
}
