###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_dos_vuln_jul13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# RealNetworks RealPlayer Denial of Service Vulnerability - July13 (Win)
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
tag_impact = "
  Impact Level: Application";

if(description)
{
  script_id(803910);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-3299");
  script_bugtraq_id(60903);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-07-17 16:46:46 +0530 (Wed, 17 Jul 2013)");
  script_name("RealNetworks RealPlayer Denial of Service Vulnerability - July13 (Win)");

  tag_summary =
"This host is installed with RealPlayer which is prone to Denial of
Service vulnerability.";

  tag_insight =
"Flaw within the unknown function of the component HTML Handler.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_impact =
"Successful exploitation allows remote attackers to cause denial of service
condition via crafted HTML file.";

  tag_affected =
"RealPlayer versions 16.0.2.32 and prior on Windows.";

  tag_solution =
"No solution or patch is available as of 25th July, 2013. Information
regarding this issue will be updated once the solution details are available.
For updates refer to http://www.real.com/player ";

  desc = "
  Summary:
  " + tag_summary + "

  Vulnerability Detection:
  " + tag_vuldetect + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "summary" , value : tag_summary);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://www.osvdb.org/94806");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1028732");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2013/Jul/18");
  script_summary("Check for the vulnerable version of RealPlayer on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}


include("version_func.inc");

##Variable Initialization
rpVer = "";

## Get RealPlayer Version
rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

## Check for Realplayer version <= 16.0.2.32
if(version_is_less_equal(version:rpVer, test_version:"16.0.2.32"))
{
  security_warning(0);
  exit(0);
}
