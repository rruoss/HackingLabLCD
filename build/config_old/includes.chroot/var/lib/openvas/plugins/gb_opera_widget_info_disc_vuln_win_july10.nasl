###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_widget_info_disc_vuln_win_july10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Opera Browser 'widget' Information Disclosure Vulnerability july-10 (Win)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation will let attackers to obtain potentially sensitive
  information via a crafted web site.
  Impact Level: Application";
tag_affected = "Opera version prior to 10.50 on Windows.";
tag_insight = "The flaw is due to error in handling of 'widget' properties, which
  makes widget properties accessible to third-party domains.";
tag_solution = "Upgrade to Opera 10.50 or later,
  For updates refer to http://www.opera.com/download/?os=windows&list=all";
tag_summary = "The host is installed with Opera web browser and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_id(801371);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-07-16 18:57:03 +0200 (Fri, 16 Jul 2010)");
  script_cve_id("CVE-2010-2659");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_name("Opera Browser 'widget' Information Disclosure Vulnerability july-10 (Win)");
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
  script_xref(name : "URL" , value : "http://www.opera.com/support/search/view/959/");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/mac/1052/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/1673");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1050/");

  script_description(desc);
  script_summary("Check for the version of Opera web browser");
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

## Get Opera version from from KB list
operaVer = get_kb_item("Opera/Win/Version");
if(!operaVer){
  exit(0);
}

## Check if version is lesser than 10.50
if(version_is_less(version:operaVer, test_version:"10.50")){
  security_warning(0);
}
