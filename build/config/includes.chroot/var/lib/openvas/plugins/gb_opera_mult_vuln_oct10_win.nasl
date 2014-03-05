###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_oct10_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Opera Browser Multiple Vulnerabilities October-10 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary code
  on the target user's system, can obtain potentially sensitive information.
  Impact Level: Application";
tag_affected = "Opera Web Browser Version prior 10.63";
tag_insight = "Multiple flaws are cause due to:
  - Failure to prevent interpretation of a 'cross-origin' document as a 'CSS'
    stylesheet when the document lacks a CSS token sequence.
  - An error when altering the size of the browser window may cause the wrong
    part of the URL of a web page to be displayed.
  - An error in the handling of reloads and redirects combined with caching may
    result in scripts executing in the wrong security context.
  - Failure to properly verify the origin of video content, which allows remote
    attackers to obtain sensitive information by using a video stream as HTML5
    canvas content.
  - Failure to properly restrict web script in unspecified circumstances involving
    reloads and redirects.
  - Failure to properly select the security context of JavaScript code associated
    with an error page.
  - Error in 'SVG' document in an 'IMG' element.";
tag_solution = "Upgarde to Opera Web Browser Version 10.63 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801474);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-10-28 11:50:37 +0200 (Thu, 28 Oct 2010)");
  script_cve_id("CVE-2010-4043", "CVE-2010-4044", "CVE-2010-4046", "CVE-2010-4045",
                "CVE-2010-4047", "CVE-2010-4049", "CVE-2010-4048", "CVE-2010-4050");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Opera Browser Multiple Vulnerabilities October-10 (Windows)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41740");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/971/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1063/");
  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Oct/1024570.html");

  script_description(desc);
  script_summary("Check for the version of Opera");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
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

## Get Opera Version from KB
operaVer = get_kb_item("Opera/Win/Version");

if(operaVer)
{
  ## Grep for Opera Versions prior to 10.63
  if(version_is_less(version:operaVer, test_version:"10.63")){
    security_hole(0);
  }
}
