###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_indesign_bof_vuln.nasl 14 2013-10-27 12:33:37Z jan $
#
# Adobe InDesign 'INDD' File Handling Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  by tricking a user into opening a specially crafted file.
  Impact Level: Application.";
tag_affected = "Adobe InDesign CS3 10.0";

tag_insight = "The flaw exists due to improper bounds checking when parsing 'INDD' files,
  which leads to buffer overflow.";
tag_solution = "Upgrade to Adobe InDesign CS5 or later.
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe InDesign and is prone
  to buffer overflow vulnerability.";

if(description)
{
  script_id(902085);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-06-25 16:56:31 +0200 (Fri, 25 Jun 2010)");
  script_cve_id("CVE-2010-2321");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Adobe InDesign 'INDD' File Handling Remote Buffer Overflow Vulnerability");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40050");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/59132");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1347");

  script_description(desc);
  script_summary("Check for the version of Adobe InDesign");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("secpod_adobe_indesign_detect.nasl");
  script_require_keys("SMB/WindowsVersion");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
  }
  exit(0);
}


include("version_func.inc");

## Get version from KB
adVer = get_kb_item("Adobe/InDesign/Ver");
if(isnull(adVer)){
  exit(0);
}

adobeVer = eregmatch(pattern:" ([0-9.]+)", string:adVer);
if(!isnull(adobeVer[1]) && ("CS3" >< adVer))
{
  ## Check for Adobe InDesign CS3 version equals to 10.0
  if(version_is_equal(version:adobeVer[1], test_version:"10.0") ){
    security_hole(0);
  }
}
