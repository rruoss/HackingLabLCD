###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_chrome_mult_vuln01_may13_lin.nasl 11 2013-10-27 10:12:02Z jan $
#
# Google Chrome Multiple Vulnerabilities-01 May13 (Linux)
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
tag_impact = "Successful exploitation will allow attackers to execute arbitrary code or
  disclose sensitive information, conduct cross-site scripting attacks and
  compromise a users system.
  Impact Level: System/Application";

tag_affected = "Google Chrome version prior to 27.0.1453.93 on Linux";
tag_insight = "For more information about the vulnerabilities refer the reference links.";
tag_solution = "Upgrade to the Google Chrome 27.0.1453.93 or later,
  For updates refer to http://www.google.com/chrome";
tag_summary = "The host is installed with Google Chrome and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803705);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-2836", "CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839",
                "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843",
                "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847",
                "CVE-2013-2848", "CVE-2013-2849");
  script_bugtraq_id(60062, 60065, 60072, 60074, 60064, 60066, 60067, 60068, 60069,
                    60076, 60070, 60071, 60073, 60063);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-05-24 11:44:26 +0530 (Fri, 24 May 2013)");
  script_name("Google Chrome Multiple Vulnerabilities-01 May13 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53430");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1028588");
  script_xref(name : "URL" , value : "http://googlechromereleases.blogspot.in/2013/05/stable-channel-release.html");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_summary("Check the vulnerable version of Google Chrome on Linux");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_lin.nasl");
  script_mandatory_keys("Google-Chrome/Linux/Ver");
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
chromeVer = "";

## Get the version from KB
chromeVer = get_kb_item("Google-Chrome/Linux/Ver");
if(!chromeVer){
  exit(0);
}

## Check for Google Chrome Version less than 27.0.1453.93
if(version_is_less(version:chromeVer, test_version:"27.0.1453.93"))
{
  security_hole(0);
  exit(0);
}
