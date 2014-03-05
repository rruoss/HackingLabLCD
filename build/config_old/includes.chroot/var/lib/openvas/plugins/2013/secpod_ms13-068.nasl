###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-068.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft Outlook Remote Code Execution Vulnerability (2756473)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

if(description)
{
  script_id(903400);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3870");
  script_bugtraq_id(62188);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-09-11 15:21:46 +0530 (Wed, 11 Sep 2013)");
  script_name("Microsoft Outlook Remote Code Execution Vulnerability (2756473)");

  tag_summary =
"This host is missing a critical security update according to
Microsoft Bulletin MS13-068.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to a double-free error within the 'CSMime::SMIMEINFOToOptions()'
function when handling nested signed S/MIME email messages.";

  tag_impact =
"Successful exploitation will allow remote attackers to execute the arbitrary
code and compromise a user system.

Impact Level: System/Application ";

  tag_affected =
"Microsoft Outlook 2007 Service Pack 3 and prior
Microsoft Outlook 2010 Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-068";

 desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54729");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2825999");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2794707");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-068");
  script_summary("Check for the version of 'Outlook.exe' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Outloook/Version");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");

# Variable Initialization
outlookVer = "";

## Check for Office outlook 2007 and 2010
outlookVer = get_kb_item("SMB/Office/Outloook/Version");
if(outlookVer && outlookVer =~ "^(12|14)\..*")
{
  if(version_in_range(version:outlookVer, test_version:"12.0", test_version2:"12.0.6680.4999") ||
     version_in_range(version:outlookVer, test_version:"14.0", test_version2:"14.0.7105.4999"))
  {
    security_hole(0);
    exit(0);
  }
}
