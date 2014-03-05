###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-076_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Office Remote Code Execution Vulnerabilities - 2720184 (Mac OS X)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code
  with the privileges of the user running the affected application.
  Impact Level: System/Application";
tag_affected = "Microsoft Office 2008 for Mac
  Microsoft Office 2011 for Mac";
tag_insight = "- An error when processing the 'SerAuxErrBar' record can be exploited to
    cause a heap-based buffer overflow via a specially crafted file.
  - An input validation error can be exploited to corrupt memory via a
    specially crafted file.
  - A use-after-free error when processing the 'SST' record can be
    exploited via a specially crafted file.
  - An error when processing certain data structures can be exploited to
    cause a stack-based buffer overflow via a specially crafted file.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS12-076";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-076.";

if(description)
{
  script_id(902931);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1885", "CVE-2012-1886", "CVE-2012-1887", "CVE-2012-2543");
  script_bugtraq_id(56425, 56426, 56430, 56431);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-14 08:55:19 +0530 (Wed, 14 Nov 2012)");
  script_name("Microsoft Office Remote Code Execution Vulnerabilities - 2720184 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51242/");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-076");

  script_description(desc);
  script_copyright("Copyright (C) 2012 SecPod");
  script_summary("Check the version of Microsoft Office for Mac");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_require_keys("MS/Office/MacOSX/Ver");
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

## Variable Initialization
offVer = "";

## Get the version from KB
offVer = get_kb_item("MS/Office/MacOSX/Ver");
if(!offVer){
  exit(0);
}

## Check for Office Version 2008(12.3.5) and 2011 (14.2.5)
if(version_in_range(version:offVer, test_version:"12.0", test_version2:"12.3.4")||
   version_in_range(version:offVer, test_version:"14.0", test_version2:"14.2.4")){
  security_hole(0);
}
