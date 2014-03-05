###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_sketchup_skp_file_mem_corruption_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Google SketchUp '.SKP' File Memory Corruption Vulnerability (Mac OS X)
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
tag_impact = "Successful exploitation will allow the attacker to execute arbitrary code in
  the context of the user running the application which can compromise the
  application and possibly the system.
  Impact Level: System/Application";
tag_affected = "Google SketchUp version 8 Maintenance Release 2 and prior on Mac OS X";
tag_insight = "SketchUp fails to parse specially crafted SketchUp document (SKP) files and
  can be exploited to execute arbitrary code or cause a denial of service
  (memory corruption) via a crafted SKP file.";
tag_solution = "Upgrade to Google SketchUp version 8 Maintenance Release 3 or later,
  For updates refer to http://sketchup.google.com/download/index2.html";
tag_summary = "This host is installed with Google SketchUp and is prone to
  to memory corruption vulnerability.";

if(description)
{
  script_id(803039);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-4894");
  script_bugtraq_id(55598);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-10-09 17:33:06 +0530 (Tue, 09 Oct 2012)");
  script_name("Google SketchUp '.SKP' File Memory Corruption Vulnerability (Mac OS X)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/85570");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50663");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/msvr/msvr12-015");

  script_description(desc);
  script_summary("Check for the version of Google SketchUp 8.0.11751.0 on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_google_sketchup_detect_macosx.nasl");
  script_require_keys("Google/SketchUp/MacOSX/Version");
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
gsVer = "";

## Get the version from KB
gsVer = get_kb_item("Google/SketchUp/MacOSX/Version");
if(!gsVer){
  exit(0);
}

# Check for Google SketchUp 8.0 m2 (8.0.11752.0) and prior
if(version_is_less_equal(version:gsVer, test_version:"8.0.11751.0")){
  security_hole(0);
}
