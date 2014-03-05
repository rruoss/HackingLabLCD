###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_dos_vuln_win_jan10.nasl 14 2013-10-27 12:33:37Z jan $
#
# Firefox 'nsObserverList::FillObserverArray' DOS Vulnerability (Win)
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
tag_impact = "Successful remote exploitation will allow attackers to  crash application
  via a crafted web site that triggers memory consumption and an accompanying
  Low Memory alert dialog, and also triggers attempted removal of an observer
  from an empty observers array.
  Impact Level: Application.";
tag_affected = "Mozilla Firefox version prior to 3.5.7 on Windows.";
tag_insight = "The flaw is due to error in 'nsObserverList::FillObserverArray()' function
  in 'xpcom/ds/nsObserverList.cpp'";
tag_solution = "Upgrade to Firefox version 3.5.7
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Mozilla Firefox browser and is prone to
  Denial of Service vulnerability.";

if(description)
{
  script_id(800416);
  script_version("$Revision: 14 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:33:37 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2010-0220");
  script_name("Firefox 'nsObserverList::FillObserverArray' DOS Vulnerability (Win)");
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
  script_xref(name : "URL" , value : "http://isc.sans.org/diary.html?storyid=7897");
  script_xref(name : "URL" , value : "https://bugzilla.mozilla.org/show_bug.cgi?id=507114");
  script_xref(name : "URL" , value : "http://www.mozilla.com/en-US/firefox/3.5.7/releasenotes");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_require_keys("Firefox/Win/Ver");
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

firefoxVer = get_kb_item("Firefox/Win/Ver");
if(!firefoxVer){
  exit(0);
}

if(version_is_less(version:firefoxVer, test_version:"3.5.7")){
  security_warning(0);
}
