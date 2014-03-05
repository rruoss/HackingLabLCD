###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_sjow_arbitrary_code_exec_vuln_win.nasl 14 2013-10-27 12:33:37Z jan $
#
# Mozilla Products 'SJOW' Arbitrary Code Execution Vulnerability (Windows)
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
tag_solution = "Upgrade to Firefox version 3.6.9 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version 3.1.3
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will let attackers to execute arbitrary Java script
  code with privileges.
  Impact Level: Application";
tag_affected = "Firefox version 3.6.x before 3.6.9
  Thunderbird version 3.1.x before 3.1.3";
tag_insight = "The flaw is due to error in 'XPCSafeJSObjectWrapper' class in the
  'SafeJSObjectWrapper', which does not properly restrict objects at the
  end of scope chains.";
tag_summary = "The host is installed with Mozilla Firefox/Thunderbird that are prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801452);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-09-10 16:37:50 +0200 (Fri, 10 Sep 2010)");
  script_cve_id("CVE-2010-2762");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_name("Mozilla Products 'SJOW' Arbitrary Code Execution Vulnerability (Windows)");
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

  script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2010/Sep/1024403.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2010/mfsa2010-59.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl", "gb_thunderbird_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver", "Thunderbird/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "solution" , value : tag_solution);
  }
  exit(0);
}


include("version_func.inc");

## Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(ffVer)
{
  ## Grep for Firefox version 3.6 < 3.6.9
  if(version_in_range(version:ffVer, test_version:"3.6", test_version2:"3.6.8"))
  {
    security_hole(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version 3.1 < 3.1.3
  if(version_in_range(version:tbVer, test_version:"3.1", test_version2:"3.1.2")){
    security_hole(0);
  }
}
