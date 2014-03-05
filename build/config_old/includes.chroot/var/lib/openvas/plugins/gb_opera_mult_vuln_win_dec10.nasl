###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_win_dec10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Opera Browser Multiple Vulnerabilities December-10 (Windows)
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
tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information and cause a denial of service.
  Impact Level: Application";
tag_affected = "Opera Web Browser Version prior 11.00";
tag_insight = "Multiple flaws are cause due to:
  - WAP fails to clear 'WML' form fields after manual navigation to a new web
    site, which allows remote attackers to obtain sensitive information.
  - Not properly constrain dialogs to appear on top of rendered documents.
  - Unspecified vulnerability which has unknown impact and attack vectors.
  - Not display a page's security indication, when Opera Turbo is enabled.
  - Not properly handling security policies during updates to extensions.
  - Fails to present information about problematic 'X.509' certificates on
    https web sites, when 'Opera Turbo' is used.
  - Unspecified vulnerability in the auto-update functionality, which leads
    to a denial of service.
  - Fails to implement the Insecure Third Party Module warning message.
  - Enabling 'WebSockets' functionality, which has unspecified impact and
    remote attack vectors.";
tag_solution = "Upgarde to Opera Web Browser Version 11.00 or later,
  For updates refer to http://www.opera.com/download/";
tag_summary = "The host is installed with Opera browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801495);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-12-27 09:55:05 +0100 (Mon, 27 Dec 2010)");
  script_cve_id("CVE-2010-4579", "CVE-2010-4580", "CVE-2010-4581", "CVE-2010-4582",
                "CVE-2010-4583", "CVE-2010-4584", "CVE-2010-4585", "CVE-2010-4586",
                "CVE-2010-4587");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Opera Browser Multiple Vulnerabilities December-10 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/979/");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/977/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1100/");

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
  ## Grep for Opera Versions prior to 11.00
  if(version_is_less(version:operaVer, test_version:"11.00")){
    security_hole(0);
  }
}
