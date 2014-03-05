###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_photoshop_png_image_file_bof_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Photoshop PNG Image Processing Buffer Overflow Vulnerabilities (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code.
  Impact Level: System/Application";
tag_affected = "Adobe Photoshop version prior to CS6 (13.0) on Mac OS X";
tag_insight = "- A boundary error in the 'Standard MultiPlugin.8BF' module fails to
    process a Portable Network Graphics (PNG) image, which allows attacker to
    cause a buffer overflow via a specially crafted 'tRNS' chunk size.
  - Improper validation in Photoshop.exe when decompressing
    SGI24LogLum-compressed TIFF images.";
tag_solution = "Upgrade to Adobe Photoshop version CS6 (13.0.1) or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Photoshop and is prone to buffer
  overflow vulnerabilities.";

if(description)
{
  script_id(803026);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4170", "CVE-2012-0275");
  script_bugtraq_id(55333, 55372);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-09-03 18:23:45 +0530 (Mon, 03 Sep 2012)");
  script_name("Adobe Photoshop PNG Image Processing Buffer Overflow Vulnerabilities (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://osvdb.org/85006");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49141");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-20.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Photoshop on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_photoshop_detect_macosx.nasl");
  script_require_keys("Adobe/Photoshop/MacOSX/Version");
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
photoVer = "";

photoVer = get_kb_item("Adobe/Photoshop/MacOSX/Version");
if(!photoVer){
  exit(0);
}

photoVer = eregmatch(pattern:"([0-9.]+)", string:photoVer);
if(photoVer[0])
{
  ## Check for Adobe Photoshop versions with patch
  ## Adobe Photoshop CS6(13.0)
  if(version_is_equal(version:photoVer[0], test_version:"13.0")){
    security_hole(0);
  }
}
