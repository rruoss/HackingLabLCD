###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-034_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Microsoft Silverlight Code Execution Vulnerabilities - 2681578 (Mac OS X)
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
tag_impact = "Successful exploitation could allow attackers to execute arbitrary code by
  tricking a user into opening a specially crafted file.
  Impact Level: System/Application";
tag_affected = "Microsoft Silverlight versions 4 and 5";
tag_insight = "The flaws are due to an error exists when parsing TrueType fonts.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS12-034";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-034.";

if(description)
{
  script_id(902678);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3402", "CVE-2012-0159");
  script_bugtraq_id(50462, 53335);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-14 13:06:50 +0530 (Mon, 14 May 2012)");
  script_name("Microsoft Silverlight Code Execution Vulnerabilities - 2681578 (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49121");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2681578");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2690729");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027048");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-034");

  script_description(desc);
  script_copyright("Copyright (C) 2012 SecPod");
  script_summary("Check the version of Microsoft Silverlight for Mac");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_ms_silverlight_detect_macosx.nasl");
  script_require_keys("MS/Silverlight/MacOSX/Ver");
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
slightVer = "";

## Get the version from KB
slightVer = get_kb_item("MS/Silverlight/MacOSX/Ver");
if(!slightVer){
  exit(0);
}

## Check for Silverlight 4 and 5
if(version_in_range(version: slightVer, test_version:"4.0", test_version2:"4.1.10328")||
   version_in_range(version: slightVer, test_version:"5.0", test_version2:"5.1.10410")){
  security_hole(0);
}
