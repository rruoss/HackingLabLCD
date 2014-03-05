###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_lin_mar12.nasl 12 2013-10-27 11:15:33Z jan $
#
# Adobe Flash Player Multiple Vulnerabilities (Linux) - Mar12
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
tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Adobe Flash Player version before 10.3.183.16 on Linux
  Adobe Flash Player version 11.x before 11.1.102.63 on Linux";
tag_insight = "The flaws are due to an integer errors and Unspecified error in Matrix3D
  component.";
tag_solution = "Upgrade to Adobe Flash Player version 10.3.183.16 or 11.1.102.63 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(802810);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-0769", "CVE-2012-0768");
  script_bugtraq_id(52299, 52297);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-03-12 18:30:17 +0530 (Mon, 12 Mar 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Linux) - Mar12");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48281/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-05.html");

  script_description(desc);
  script_summary("Check for the version of Adobe Flash Player");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_require_keys("AdobeFlashPlayer/Linux/Ver");
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

# Variable Initialization
flashVer = NULL;

# Get Adobe Flash Player Version
flashVer = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(isnull(flashVer)){
  exit(0);
}

flashVer = ereg_replace(pattern:",", string:flashVer, replace: ".");

## Check for Adobe Flash Player versions before 10.3.183.16 and 11.1.102.63
if(version_is_less(version:flashVer, test_version:"10.3.183.16")||
   version_in_range(version:flashVer, test_version:"11.0", test_version2:"11.1.102.62")){
  security_hole(0);
}
