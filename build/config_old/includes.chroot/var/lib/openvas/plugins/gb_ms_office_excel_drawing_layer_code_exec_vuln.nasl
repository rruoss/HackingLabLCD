###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_excel_drawing_layer_code_exec_vuln.nasl 13 2013-10-27 12:16:33Z jan $
#
# Microsoft Excel 2007 Office Drawing Layer Remote Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attacker to execute arbitrary codes,
  cause memory corruption and other attacks in the context of the application
  through crafted Excel file.
  Impact Level: System";
tag_affected = "Microsoft Office Excel 2007";
tag_insight = "The flaw exists in office drawing file format. When parsing shape data within
  a particular container, the application fails to remove the reference to an
  object when an error occurs.";
tag_solution = "No solution or patch is available as of 17th February, 2011. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://office.microsoft.com/en-us/excel/";
tag_summary = "This host is installed with Microsoft Office Excel and is prone to
  remote code execution vulnerability.

  This NVT has been replaced by NVT secpod_ms11-023.nasl
  (OID:1.3.6.1.4.1.25623.1.0.902364).";
if(description)
{
  script_id(801596);
  script_version("$Revision: 13 $");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2011-0977");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_bugtraq_id(46225);
  script_name("Microsoft Excel 2007 Office Drawing Layer Remote Code Execution Vulnerability");
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
  script_xref(name : "URL" , value : "http://zerodayinitiative.com/advisories/ZDI-11-043/");
  script_xref(name : "URL" , value : "http://dvlabs.tippingpoint.com/blog/2011/02/07/zdi-disclosure-microsoft");

  script_description(desc);
  script_summary("Check for the version of Microsoft Excel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("secpod_office_products_version_900032.nasl",
                      "secpod_ms_office_detection_900025.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/Office/Excel/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}

exit(66); ## This NVT is deprecated as addressed in secpod_ms11-023.nasl.


if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

## check for microsoft office installation
if(!get_kb_item("MS/Office/Ver") =~ "^12\.*"){
  exit(0);
}

## Get the ms office Excel version
excelVer = get_kb_item("SMB/Office/Excel/Version");

## Check for the MS office power point 2007
if(excelVer &&  excelVer =~ "^12\.*"){
  security_hole(0);
}
