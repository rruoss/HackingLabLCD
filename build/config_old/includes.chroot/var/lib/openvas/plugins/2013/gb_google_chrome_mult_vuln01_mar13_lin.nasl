###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_mar13_lin.nasl 11 2013-10-27 10:12:02Z jan $
#
# Google Chrome Multiple Vulnerabilities-01 March 2013 (Linux)
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the browser, bypass security restrictions, cause
  denial-of-service condition or possibly have unspecified other impact.
  Impact Level: System/Application";

tag_affected = "Google Chrome versions prior to 25.0.1364.97 on linux";
tag_insight = "For more details about the vulnerabilities refer the reference section.";
tag_solution = "Upgrade to the Google Chrome 25.0.1364.97 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803314);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0879","CVE-2013-0880","CVE-2013-0881","CVE-2013-0882",
                "CVE-2013-0883","CVE-2013-0884","CVE-2013-0885","CVE-2013-0887",
                "CVE-2013-0888","CVE-2013-0889","CVE-2013-0890","CVE-2013-0891",
                "CVE-2013-0892","CVE-2013-0893","CVE-2013-0894","CVE-2013-0895",
                "CVE-2013-0896","CVE-2013-0897","CVE-2013-0898","CVE-2013-0899",
                "CVE-2013-0900","CVE-2013-2268");
  script_bugtraq_id(58101);
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:P/A:P");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-03-01 10:16:26 +0530 (Fri, 01 Mar 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 March 2013 (Linux)");
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
  script_xref(name : "URL" , value : "http://en.securitylab.ru/nvd/438026.php");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52320");
  script_xref(name : "URL" , value : "http://www.dhses.ny.gov/ocs/advisories/2013/2013-021.cfm");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/02/stable-channel-update_21.html");

  script_description(desc);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check for the vulnerable version of Google Chrome on Linux");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl", "ssh_authorization_init.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
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
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Versions prior to 25.0.1364.97
if(version_is_less(version:chromeVer, test_version:"25.0.1364.97")){
  security_hole(0);
  exit(0);
}
