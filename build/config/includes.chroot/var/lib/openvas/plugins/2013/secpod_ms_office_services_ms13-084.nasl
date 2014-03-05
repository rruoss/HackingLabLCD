###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_services_ms13-084.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft Office Services Remote Code Execution vulnerability (2885089)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903328";
CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3889", "CVE-2013-3895");
  script_bugtraq_id(62829, 62800);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-09 17:36:47 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Services Remote Code Execution vulnerability (2885089)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS13-084.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is due to improper sanitation of user supplied input via a specially
crafted Excel file.";

  tag_impact =
"Successful exploitation will allow attackers to execute arbitrary code,
cause a DoS (Denial of Service), and compromise a vulnerable system.

Impact Level: System/Application";

  tag_affected =
"Excel Services on Microsoft SharePoint Server 2007/2010/2013,
Word Automation Services on Microsoft SharePoint Server 2010/2013.";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms13-084";

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
  script_xref(name : "URL" , value : "http://www.osvdb.com/98219");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/55131");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-084");
  script_summary("Check for the vulnerable file version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
shareVer = "";
dllVer = "";
path = "";

## Get SharePoint Version
shareVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID);
if(!shareVer){
  exit(0);
}

path = get_app_location(cpe:CPE, nvt:SCRIPT_OID);
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Server 2007 (wosrv & coreserver)
if(shareVer =~ "^12\..*")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\12.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6683.5001"))
    {
      security_hole(0);
      exit(0);
    }
  }
}

## SharePoint Server 2010
if(shareVer =~ "^14\..*")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\14.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7108.4999"))
    {
      security_hole(0);
      exit(0);
    }
  }

  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\WdsrvWorker.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.6112.4999"))
    {
      security_hole(0);
      exit(0);
    }
  }
}

## SharePoint Server 2013
if(shareVer =~ "^15\..*")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\15.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4535.1506"))
    {
      security_hole(0);
      exit(0);
    }
  }

  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\15.0\WebServices\ConversionServices\WdsrvWorker.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"15.0", test_version2:"15.0.4514.999"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
