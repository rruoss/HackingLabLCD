###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln02_oct13_win.nasl 29 2013-10-30 14:01:12Z veerendragg $
#
# Google Chrome Multiple Vulnerabilities-02 Oct2013 (Win)
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

CPE = "cpe:/a:google:chrome";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804114";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 29 $");
  script_cve_id("CVE-2013-2928","CVE-2013-2925","CVE-2013-2926","CVE-2013-2927");
  script_bugtraq_id(63024,63026,63028,63025);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"(AV:N/AC:M/Au:N/C:P/I:P/A:P)");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-30 15:01:12 +0100 (Mi, 30. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-10-23 14:30:38 +0530 (Wed, 23 Oct 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-02 Oct2013 (Win)");

  tag_summary =
"This host is installed with Google Chrome and is prone to multiple
vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Google Chrome and check the version
is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
-Use-after-free vulnerability in the HTMLFormElement 'prepareForSubmission'
function in core/html/HTMLFormElement.cpp.
-Use-after-free vulnerability in the IndentOutdentCommand
'tryIndentingAsListItem' function in core/editing/IndentOutdentCommand.cpp.
-Use-after-free vulnerability in core/xml/XMLHttpRequest.cpp.
-Another unspecified error.";

  tag_impact =
"Successful exploitation will allow remote attackers to cause a denial of
service or possibly have other impact via vectors related to submission
for FORM elements,vectors related to list elements,vectors that trigger
multiple conflicting uses of the same XMLHttpRequest object or via unknown
vectors.

Impact Level: Application";

  tag_affected =
"Google Chrome before 30.0.1599.101";

  tag_solution =
"Upgrade to version 30.0.1599.101 or later
For updates refer to http://www.google.com/chrome";

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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/63025");
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/446283.php");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/10/stable-channel-update_15.html");
  script_summary("Check for the vulnerable version of Google Chrome on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");
## Variable Initialization
chromeVer = "";

## Get version
if(!chromeVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:chromeVer, test_version:"30.0.1599.101"))
{
  security_hole(0);
  exit(0);
}
