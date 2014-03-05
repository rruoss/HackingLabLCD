###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_compat_pack_ms13-086.nasl 11 2013-10-27 10:12:02Z jan $
#
# MS Office Compatibility Pack Remote Code Execution Vulnerabilities (2885084)
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
  script_id(903406);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3891", "CVE-2013-3892");
  script_bugtraq_id(62827, 62832);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-09 09:18:15 +0530 (Wed, 09 Oct 2013)");
  script_name("MS Office Compatibility Pack Remote Code Execution Vulnerabilities (2885084)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS13-086.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to error when processing Microsoft Word binary
documents can be exploited to cause a memory corruption";

  tag_impact =
"Successful exploitation will allow remote attackers to execute the arbitrary
code, cause memory corruption and compromise the system.

Impact Level: System/Application ";

  tag_affected =
"Microsoft Office Compatibility Pack Service Pack 3 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-086";

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55143");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2827329");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-086");
  script_summary("Check for the version of 'Wordcnv.dll' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/WordCnv/Version");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
wordcnvVer = "";
path = "";
sysVer = "";

# Check for Office Word Version 2007 with compatibility pack
wordcnvVer = get_kb_item("SMB/Office/WordCnv/Version");
if(wordcnvVer && wordcnvVer =~ "^12.*")
{
  # Office Word Converter
  path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                              item:"ProgramFilesDir");
  if(path)
  {
    sysVer = fetch_file_version(sysPath:path + "\Microsoft Office\Office12", file_name:"Wordcnv.dll");

    if(sysVer)
    {
      # Check for Word Converter 2007 version 12.0 < 12.0.6683.5002
      if(version_in_range(version:sysVer, test_version:"12.0", test_version2:"12.0.6683.5001"))
      {
        security_hole(0);
        exit(0);
      }
    }
  }
}
