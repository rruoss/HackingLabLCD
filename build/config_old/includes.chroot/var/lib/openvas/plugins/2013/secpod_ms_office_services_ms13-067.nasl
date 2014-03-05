###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_services_ms13-067.nasl 11 2013-10-27 10:12:02Z jan $
#
# Microsoft Office Services Remote Code Execution vulnerability (2834052)
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903325";
CPE = "cpe:/a:microsoft:sharepoint_server";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-1330", "CVE-2013-3179", "CVE-2013-3180", "CVE-2013-0081",
                "CVE-2013-1315");
  script_bugtraq_id(62221, 62227, 62254, 62205, 62167);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-09 15:37:45 +0530 (Wed, 09 Oct 2013)");
  script_name("Microsoft Office Services Remote Code Execution vulnerability (2834052)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS13-067.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple Flaws are due to,
- An error when handling an unassigned workflow can be exploited to cause the
  W3WP process to stop responding via a specially crafted URL.
- An error related to MAC exists when handling unassigned workflows.
- Input passed via the 'ms-descriptionText > ctl00_PlaceHolderDialogBodySection
  _PlaceHolderDialogBodyMainSection_ValSummary' parameter related to metadata
  storage assignment of the BDC permission management within the 'Sharepoint
  Online Cloud 2013 Service' section is not properly sanitised before being used.
- Certain unspecified input is not properly sanitised before being returned to
   the user.
- Multiple unspecified errors.";

  tag_impact =
"Successful exploitation will allow attackers to conduct script insertion
attacks, cause a DoS (Denial of Service), and compromise a vulnerable system.

Impact Level: Application";

  tag_affected =
"Excel Services on Microsoft SharePoint Server 2007
Excel Services on Microsoft SharePoint Server 2010
Word Automation Services on Microsoft SharePoint Server 2010";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms13-067";

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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/54741");
  script_xref(name : "URL" , value : "http://www.vulnerability-lab.com/get_content.php?id=812");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS13-067");
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

## SharePoint Server 2010 (wosrv & coreserver)
if(shareVer =~ "^14\..*")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\14.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7104.4999"))
    {
      security_hole(0);
      exit(0);
    }
  }

  dllVer2 = fetch_file_version(sysPath:path,
            file_name:"\14.0\WebServices\WordServer\Core\WdsrvWorker.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"14.0", test_version2:"14.0.7104.4999"))
    {
      security_hole(0);
      exit(0);
    }
  }
}

## SharePoint Server 2007 (wosrv & coreserver)
if(shareVer =~ "^12\..*")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\12.0\Bin\Xlsrv.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6676.4999"))
    {
      security_hole(0);
      exit(0);
    }
  }
}
