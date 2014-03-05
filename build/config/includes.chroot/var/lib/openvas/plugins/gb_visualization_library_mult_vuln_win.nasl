###############################################################################
# Openvas Vulnerability Test
# $Id: gb_visualization_library_mult_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Visualization Library Multiple Unspecified Vulnerabilities (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
##############################################################################

include("revisions-lib.inc");
tag_impact = "Unknown impacts and unknown attack vectors.
  Impact Level: Application";
tag_affected = "Visualization Library versions prior to 2009.08.812 on Windows";
tag_insight = "The flaws are caused by multiple unspecified errors with unknown impact and
  unknown attack vectors.";
tag_solution = "Update to version 2009.08.812 or above,
  For updates refer to http://www.visualizationlibrary.com/downloads.php";
tag_summary = "The host is running Visualization Library and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801000);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2010-0937");
  script_bugtraq_id(37644);
  script_name("Visualization Library Multiple Unspecified Vulnerabilities (Windows)");
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
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/55478");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0050");
  script_xref(name : "URL" , value : "http://visualizationlibrary.com/documentation/pagchangelog.html");

  script_description(desc);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_summary("Check for the version of Visualization Library");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_visualization_library_detect_win.nasl");
  script_require_keys("VisualizationLibrary/Win/Ver");
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

## Get Visualization Library version from KB
vslVer = get_kb_item("VisualizationLibrary/Win/Ver");
if(isnull(vslVer)){
  exit(0);
}

## Check for versions prior to  2009.08.812
if(version_is_less(version:vslVer, test_version:"2009.08.812")){
  security_hole(0);
}
