###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln02_jan13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Opera Multiple Vulnerabilities-02 Jan13 (Windows)
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
tag_impact = "Successful exploitation will let the attacker crash the browser leading to
  denial of service, execute the arbitrary code or disclose the information.
  Impact Level: System/Application";

tag_affected = "Opera version before 12.11 on Windows";
tag_insight = "- An error in handling of error pages, can be used to guess local file paths.
  - An error when requesting pages using HTTP, causes a buffer overflow, which
    in turn can lead to a memory corruption and crash.";
tag_solution = "Upgrade to Opera version 12.11 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803141);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2012-6468", "CVE-2012-6469");
  script_bugtraq_id(56594);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-07 14:59:24 +0530 (Mon, 07 Jan 2013)");
  script_name("Opera Multiple Vulnerabilities-02 Jan13 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1037/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1036/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/unified/1212/");

  script_description(desc);
  script_summary("Check for the version of Opera for Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
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

operaVer = "";

## Get Opera version from KB
operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

## Check for opera versions prior to 12.11
if(version_is_less(version:operaVer, test_version:"12.11")){
  security_hole(0);
}
