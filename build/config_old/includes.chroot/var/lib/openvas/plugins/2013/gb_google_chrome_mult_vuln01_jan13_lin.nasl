###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_jan13_lin.nasl 11 2013-10-27 10:12:02Z jan $
#
# Google Chrome Multiple Vulnerabilities-01 Jan2013 (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or
  cause a denial of service.
  Impact Level: System/Application";

tag_affected = "Google Chrome version prior to 24.0.1312.52 on Linux";
tag_insight = "For more details about the vulnerabilities refer the reference section.";
tag_solution = "Upgrade to the Google Chrome 24.0.1312.52 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "This host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803158);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-5145", "CVE-2012-5146", "CVE-2012-5147", "CVE-2012-5148",
                "CVE-2012-5149", "CVE-2012-5150", "CVE-2012-5151", "CVE-2012-5152",
                "CVE-2012-5153", "CVE-2012-5156", "CVE-2012-5157", "CVE-2013-0828",
                "CVE-2013-0829", "CVE-2013-0831", "CVE-2013-0832", "CVE-2013-0833",
                "CVE-2013-0834", "CVE-2013-0835", "CVE-2013-0836", "CVE-2013-0837",
                "CVE-2013-0838");
  script_bugtraq_id(57251);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-17 14:48:24 +0530 (Thu, 17 Jan 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 Jan2013 (Linux)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/89072");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51825/");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027977");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/01/stable-channel-update.html");

  script_description(desc);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the version of Google Chrome on Linux");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl", "ssh_authorization_init.nasl");
  script_require_keys("Google-Chrome/Linux/Ver", "ssh/login/uname");
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

## Check for Google Chrome Versions prior to 24.0.1312.52
if(version_is_less(version:chromeVer, test_version:"24.0.1312.52")){
  security_hole(0);
}
