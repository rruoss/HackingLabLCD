###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_firefox_url_file_info_dis_vuln.nasl 16 2013-10-27 13:09:52Z jan $
#
# Firefox .url Shortcut File Information Disclosure Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_impact = "Successful remote exploitation could result in disclosure of sensitive
  information.
  Impact Level: System";
tag_affected = "Firefox version 3.0.1 to 3.0.3 on Windows.";
tag_insight = "The Browser does not properly identify the context of Windows .url shortcut
  files, which allows remote attackers to bypass the Same Origin Policy and
  obtain sensitive information via an HTML document that is directly accessible
  through a filesystem.";
tag_solution = "Upgrade to Firefox version 3.6.3 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all-older.html";
tag_summary = "The host is installed with Mozilla Firefox browser, that is prone
  to information disclosure vulnerability.";

if(description)
{
  script_id(800031);
  script_version("$Revision: 16 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 14:09:52 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2008-10-17 14:35:03 +0200 (Fri, 17 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2008-4582");
  script_bugtraq_id(31747);
  script_name("Firefox .url Shortcut File Information Disclosure Vulnerability");
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
  script_xref(name : "URL" , value : "http://liudieyu0.blog124.fc2.com/blog-entry-6.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/497091/100/0/threaded");

  script_description(desc);
  script_summary("Check for the version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
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

# Grep for firefox version 3.0.1 to 3.0.3
if(version_in_range(version:get_kb_item("Firefox/Win/Ver"),
                    test_version:"3.0.1", test_version2:"3.0.3")){
  security_warning(0);
}
