###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_photoshop_insecure_lib_load_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe Photoshop Insecure Library Loading Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  code and conduct DLL hijacking attacks.
  Impact Level: Application";
tag_affected = "Adobe Photoshop CS2 through CS5";
tag_insight = "The flaw is caused by application insecurely loading certain librairies
  from the current working directory, which could allow attackers to execute
  arbitrary code by tricking a user into opening a file from a network share.";
tag_solution = "No solution or patch is available as of 30th August, 2010. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Photoshop and is prone to
  Insecure Library Loading vulnerability.";

if(description)
{
  script_id(901147);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-01 09:34:36 +0200 (Wed, 01 Sep 2010)");
  script_cve_id("CVE-2010-3127");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe Photoshop Insecure Library Loading Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41060");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2170");
  script_xref(name : "URL" , value : "http://blog.zoller.lu/2010/08/cve-2010-xn-loadlibrarygetprocaddress.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Photoshop");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_photoshop_detect.nasl");
  script_require_keys("Adobe/Photoshop/Ver");
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

## Variable Initiliazation
adobeVer = "";

## Get version from KB
## Check for adobe versions CS5 and CS5.1
adobeVer = get_kb_item("Adobe/Photoshop/Ver");
if(!adobeVer || !(adobeVer =~ "CS[1-5]")){
  exit(0);
}

adobeVer = eregmatch(pattern:"(CS([0-9.]+)) ?([0-9.]+)", string: adobeVer);

if(!isnull(adobeVer[1]))
{
  ##Grep for Adobe Photoshop CS2 through CS5
  if( version_in_range(version:adobeVer[1], test_version: "CS2", test_version2: "CS5") ){
    security_hole(0);
  }
}