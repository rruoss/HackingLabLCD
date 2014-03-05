###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_xss_utf-8_vuln_win.nasl 31795 2013-10-01 09:55:08Z sep$
#
# Opera Cross-Site Scripting (XSS) Vulnerability (Win)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:opera:opera_browser";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804102";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-4705");
  script_bugtraq_id(31795);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Medium");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-01 09:52:30 +0530 (Tue, 01 Oct 2013)");
  script_name("Opera Cross-Site Scripting (XSS) Vulnerability (Win)");

  tag_summary =
"This host is installed with Opera and is prone to XSS attack.";

  tag_vuldetect =
"Get the installed version of Opera with the help of detect NVT and check
the version is vulnerable or not.";

  tag_insight =
"The flaw is due to some error when encoding settings are set to UTF-8.";

  tag_impact =
"Successful exploitation will let attacker to execute an arbitrary web
script or HTML on the user's web browser.

Impact Level: Application";

  tag_affected =
"Opera versions prior to 15.00 on Windows.";

  tag_solution =
"Upgrade to Opera version 15.00 or later,
For updates refer to http://www.opera.com";

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

  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "vuldetect" , value : tag_vuldetect);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "impact" , value : tag_impact);
  }

  script_description(desc);
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN01094166/index.html");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/jvndb/JVNDB-2013-000086");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unified/1500");
  script_summary("Check for the vulnerable version of Opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_mandatory_keys("Opera/Win/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable Initialization
operaVer = "";

## Get version
if(!operaVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:operaVer, test_version:"15.0"))
{
  security_hole(0);
  exit(0);
}
