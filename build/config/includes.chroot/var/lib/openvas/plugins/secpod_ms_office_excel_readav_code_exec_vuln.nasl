###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_office_excel_readav_code_exec_vuln.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Office Excel ReadAV Arbitrary Code Execution Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  or cause denial of service condition via a crafted XLS file.
  Impact Level: Application";
tag_affected = "Microsoft Excel Viewer 2007 Service Pack 3 and prior
  Microsoft Office 2007 Service Pack 2 and Service Pack 3";
tag_insight = "An error exists in the Microsoft Office Excel Viewer and Excel when handling
  crafted '.xls' files.";
tag_solution = "No solution or patch is available as of 08th November, 2012. Information
  regarding this issue will updated once the solution details are available.
  For updates refer to http://technet.microsoft.com/";
tag_summary = "This host is installed with Microsoft Office Excel which is prone
  to arbitrary code execution vulnerability.";

if(description)
{
  script_id(902692);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-5672");
  script_bugtraq_id(56309);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-08 14:28:19 +0530 (Thu, 08 Nov 2012)");
  script_name("Microsoft Office Excel ReadAV Arbitrary Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://osvdb.org/86623");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2012/Oct/63");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/524379");

  script_description(desc);
  script_summary("Check for the version of vulnerable Excel files");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_keys("SMB/Office/Excel/Version",
                      "SMB/Office/XLView/Version");
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
include("version_func.inc");

# Variable Initialization
excelVer = "";
excelviewVer = "";

# Check for Office Excel 2007
excelVer = get_kb_item("SMB/Office/Excel/Version");
if(excelVer =~ "^12")
{
  # Check version Excel.exe
  if(version_in_range(version:excelVer, test_version:"12.0", test_version2:"12.0.6665.5003"))
  {
    security_warning(0);
    exit(0);
  }
}

# Microsoft Office Excel Viewer 2007
excelviewVer = get_kb_item("SMB/Office/XLView/Version");
if(excelviewVer =~ "^12")
{
  # check for Xlview.exe  version
  if(version_in_range(version:excelviewVer, test_version:"12.0", test_version2:"12.0.6665.5003"))
  {
    security_warning(0);
    exit(0);
  }
}
