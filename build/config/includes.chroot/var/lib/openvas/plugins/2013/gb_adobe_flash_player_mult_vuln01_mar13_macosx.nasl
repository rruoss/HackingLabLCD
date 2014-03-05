###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln01_mar13_macosx.nasl 11 2013-10-27 10:12:02Z jan $
#
# Adobe Flash Player Multiple Vulnerabilities -01 March13 (Mac OS X)
#
# Authors:
# Arun Kallavi <karun@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or cause  denial-of-service condition.
  Impact Level: System/Application";

tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";
tag_solution = "Update to version 10.3.183.67 or 11.6.602.171,
  For updates refer to http://www.adobe.com/products/flash.html";
tag_insight = "Multiple flaws due to,
  - A flaw in the ExternalInterface ActionScript feature.
  - Firefox sandbox does not restrict privileges.
  - Buffer overflow in the Flash Player broker service.";
tag_affected = "Adobe Flash Player 10.3.183.61 and earlier, and 11.x to 11.6.602.167 on
  Mac OS X";

if(description)
{
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  script_id(803325);
  script_version("$Revision: 11 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-04 19:11:31 +0530 (Mon, 04 Mar 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2013-0648","CVE-2013-0643","CVE-2013-0504");
  script_bugtraq_id(58186,58185,58184);

  script_name("Adobe Flash Player Multiple Vulnerabilities -01 March13 (Mac OS X)");
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

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028210");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52374");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-08.html");

  script_description(desc);
  script_summary("Check for the vulnerable version of Adobe Flash Player on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
playerVer = "";

## Get Adobe Flash Player version from KB
playerVer = get_kb_item("Adobe/Flash/Player/MacOSX/Version");
if(!playerVer){
  exit(0);
}

## Check for Adobe Flash Player version prior to 10.3.183.61 or 11.6.602.167
if(version_is_less_equal(version:playerVer, test_version:"10.3.183.61") ||
   version_in_range(version:playerVer, test_version:"11.0", test_version2:"11.6.602.167"))
{
  security_hole(0);
  exit(0);
}
