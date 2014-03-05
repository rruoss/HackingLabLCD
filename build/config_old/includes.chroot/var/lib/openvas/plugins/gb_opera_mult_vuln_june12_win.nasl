###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_june12_win.nasl 12 2013-10-27 11:15:33Z jan $
#
# Opera Multiple Vulnerabilities - June12 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  script code, disclose sensitive information or spoof the originating URL
  of a trusted web site and carry out phishing-style attacks.
  Impact Level: System/Application";
tag_affected = "Opera version prior to 11.65 on Windows";
tag_insight = "- An error when displaying preferences within a small window can be exploited
    to execute arbitrary code by tricking a user into entering a specific
    keyboard sequence.
  - An error when displaying pop-up windows can be exploited to execute script
    code by tricking a user into following a specific sequence of events.
  - An error when handling JSON resources can be exploited to bypass the cross
    domain policy restriction and disclose certain information to other sites.
  - An unspecified error can be exploited to display arbitrary content while
    showing the URL of a trusted web site in the address bar.
  - An error when handling page loads can be exploited to display arbitrary
    content while showing the URL of a trusted web site in the address.";
tag_solution = "Upgrade to Opera version 11.65 or 12 or later,
  For updates refer to http://www.opera.com/";
tag_summary = "The host is installed with Opera and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(802646);
  script_version("$Revision: 12 $");
  script_bugtraq_id(54011);
  script_cve_id("CVE-2012-3555", "CVE-2012-3556", "CVE-2012-3557", "CVE-2012-3558",
                "CVE-2012-3560");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-21 15:15:15 +0530 (Thu, 21 Jun 2012)");
  script_name("Opera Multiple Vulnerabilities - June12 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49533/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1018/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1019/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1020/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1021/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/1022/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1200/");

  script_description(desc);
  script_summary("Check for the version of Opera for Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_opera_detection_win_900036.nasl");
  script_require_keys("Opera/Win/Version");
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

operaVer = "";

## Get Opera version from KB
operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

## Check for opera version is less than 11.65
if(version_is_less(version:operaVer, test_version:"11.65")){
  security_hole(0);
}
