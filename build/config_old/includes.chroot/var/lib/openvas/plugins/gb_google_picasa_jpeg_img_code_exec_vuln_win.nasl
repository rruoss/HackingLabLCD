###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_picasa_jpeg_img_code_exec_vuln_win.nasl 13 2013-10-27 12:16:33Z jan $
#
# Google Picasa JPEG Image Processing Remote Code Execution Vulnerability (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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
tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Google Picasa versions prior to 3.6 build 105.67";
tag_insight = "The flaw is due to an unspecified error, when handling certain
  properties of an image file and can be exploited via a specially crafted
  JPEG image.";
tag_solution = "Upgrade to the Google Picasa 3.6 build 105.67 or later,
  For updates refer to http://picasa.google.com/thanks.html";
tag_summary = "This host is installed with google picasa and is prone to remote
  code execution vulnerability.";

if(description)
{
  script_id(802313);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-08-05 09:04:20 +0200 (Fri, 05 Aug 2011)");
  script_cve_id("CVE-2011-2747");
  script_bugtraq_id(48725);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Google Picasa JPEG Image Processing Remote Code Execution Vulnerability (Windows)");
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


  script_description(desc);
  script_summary("Check for the version of Google Picasa");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_picasa_detect_win.nasl");
  script_require_keys("Google/Picasa/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45293");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/advisory/msvr11-008.mspx");
  script_xref(name : "URL" , value : "http://picasa.google.com/support/bin/static.py?hl=en&amp;page=release_notes.cs&amp;from=53209&amp;rd=1");
  exit(0);
}


include("version_func.inc");

## Get the version from KB
picVer = get_kb_item("Google/Picasa/Win/Ver");
if(!picVer){
  exit(0);
}

## Check for Google Chrome Version less than 3.6 build 105.67
if(version_is_less(version:picVer, test_version:"3.6.105.67")){
  security_hole(0);
}
