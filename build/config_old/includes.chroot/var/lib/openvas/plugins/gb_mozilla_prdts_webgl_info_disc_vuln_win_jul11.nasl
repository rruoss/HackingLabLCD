###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_webgl_info_disc_vuln_win_jul11.nasl 13 2013-10-27 12:16:33Z jan $
#
# Mozilla Products WebGL Information Disclosure Vulnerability July-11 (Windows)
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
tag_solution = "Upgrade to Firefox version 5.0 or later.
  http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Thunderbird version 5.0 or later
  http://www.mozillamessaging.com/en-US/thunderbird/";

tag_impact = "Successful exploitation will allow remote attackers to obtain potentially
  sensitive information.
  Impact Level: Application";
tag_affected = "Thunderbird versions before 5.0
  Mozilla Firefox versions before 5.0";
tag_insight = "The flaw is due to an error in WebGL, which allows remote attackers to
  obtain approximate copies of arbitrary images via a timing attack involving
  a crafted WebGL fragment shader.";
tag_summary = "The host is installed with Mozilla Firefox or Thunderbird and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(802211);
  script_version("$Revision: 13 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:16:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2011-07-07 15:43:33 +0200 (Thu, 07 Jul 2011)");
  script_cve_id("CVE-2011-2366");
  script_bugtraq_id(48319);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Mozilla Products WebGL Information Disclosure Vulnerability July-11 (Windows)");
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

  script_xref(name : "URL" , value : "http://www.contextis.co.uk/resources/blog/webgl/");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=656277");
  script_xref(name : "URL" , value : "https://developer.mozilla.org/en/WebGL/Cross-Domain_Textures");
  script_xref(name : "URL" , value : "https://hacks.mozilla.org/2011/06/cross-domain-webgl-textures-disabled-in-firefox-5/");

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
  ## Grep for Firefox version before 5.0
  if(version_is_less(version:ffVer, test_version:"5.0"))
  {
    security_warning(0);
    exit(0);
  }
}

## Thunderbird Check
tbVer = get_kb_item("Thunderbird/Win/Ver");
if(tbVer != NULL)
{
  ## Grep for Thunderbird version before 5.0
  if(version_is_less(version:tbVer, test_version:"5.0")){
    security_warning(0);
  }
}
