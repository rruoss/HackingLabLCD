###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_unspecified_vuln_win_may11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mozilla Products Unspecified Vulnerability May-11 (Windows)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Firefox version 3.6.17, 4.0.1 or later
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version 3.1.10 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will let remote attackers to a cause a denial of
  service or possibly execute arbitrary code.
  Impact Level: Application";
tag_affected = "Thunderbird 3.1.x before 3.1.10
  Mozilla Firefox versions 3.6.x before 3.6.17 and 4.x before 4.0.1";
tag_insight = "The flaw is due to unspecified vulnerability in the browser engine
  which allows remote attackers to cause a denial of service or possibly
  execute arbitrary code via unknown vectors.";
tag_summary = "The host is installed with Mozilla Firefox or Thunderbird and is prone to
  unspecified vulnerability.";

if(description)
{
  script_id(801887);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_cve_id("CVE-2011-0081");
  script_bugtraq_id(47653);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_name("Mozilla Products Unspecified Vulnerability May-11 (Windows)");
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

  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/1127");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=645289");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2011/mfsa2011-12.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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
  ## Grep for Firefox versions 4.x before 4.0.1
  if(version_in_range(version:ffVer, test_version:"3.6.0", test_version2:"3.6.16") ||
     version_in_range(version:ffVer, test_version:"4.0", test_version2:"4.0.b12")) {
    security_hole(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version  3.1.x before 3.1.10
  if(version_in_range(version:ffVer, test_version:"3.1.0", test_version2:"3.1.9")){
    security_hole(0);
  }
}
