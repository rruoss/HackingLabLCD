###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_quicktime_mult_vuln_nov12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apple QuickTime Multiple Vulnerabilities - Nov12 (Windows)
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  cause a buffer overflow condition.
  Impact Level: System/Application";
tag_affected = "QuickTime Player version prior to 7.7.3 on Windows";
tag_insight = "- Multiple boundary errors exists when handling a PICT file, a Targa file,
    the transform attribute of 'text3GTrack' elements and the 'rnet' box
    within MP4 file.
  - Use-after-free errors exists when handling '_qtactivex_' parameters within
    an HTML object and 'Clear()' method.";
tag_solution = "Upgrade to QuickTime Player version 7.7.3 or later,
  For updates refer to http://support.apple.com/downloads/";
tag_summary = "This host is installed with Apple QuickTime and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803047);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-1374", "CVE-2012-3757", "CVE-2012-3751", "CVE-2012-3758",
                "CVE-2012-3752", "CVE-2012-3753", "CVE-2012-3754", "CVE-2012-3755",
                "CVE-2012-3756");
  script_bugtraq_id(56438);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-11-09 13:08:03 +0530 (Fri, 09 Nov 2012)");
  script_name("Apple QuickTime Multiple Vulnerabilities - Nov12 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/87094");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5581");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51226");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2012/Nov/msg00002.html");

  script_description(desc);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_summary("Check for the version of QuickTime Player on Windows");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_apple_quicktime_detection_win_900124.nasl");
  script_require_keys("QuickTime/Win/Ver");
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
quickVer = "";

## Get the version from KB
quickVer = get_kb_item("QuickTime/Win/Ver");
if(!quickVer){
  exit(0);
}

## Check for QuickTime Player Version less than 7.7.3
if(version_is_less(version:quickVer, test_version:"7.7.3")){
  security_hole(0);
}
