###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_addr_bar_spoofing_vuln_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Products Address Bar Spoofing Vulnerability (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation lets the attackers to spoof parts of the address bar
  and modify page content on a host that a user may consider partly trusted.
  Impact Level: Application";
tag_affected = "Mozilla Firefox version 3.5.1 and 3.5.2, Seamonkey 1.1.17 and on Linux.";
tag_insight = "Error exists when opening a new window using 'window.open()', which can be
  exploited to display spoofed content in the browser window while the address
  bar shows an arbitrary path on a possibly trusted host.";
tag_solution = "No solution or patch is available as of 02nd September, 2009. Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://www.mozilla.com/en-US/";
tag_summary = "This host is installed with Mozilla Products and is prone to Address
  Bar Spoofing vulnerability.";

if(description)
{
  script_id(800876);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-02 11:50:45 +0200 (Wed, 02 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3007");
  script_name("Mozilla Products Address Bar Spoofing Vulnerability (Linux)");
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
  script_xref(name : "URL" , value : "http://lostmon.blogspot.com/2009/08/multiple-browsers-fake-url-folder-file.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Products");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl",
                      "gb_seamonkey_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver", "Seamonkey/Linux/Ver");
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

# Firefox Check
ffVer = get_kb_item("Firefox/Linux/Ver");

if(ffVer)
{
  # Grep for Firefox version 3.5.1 and 3.5.2
  if(version_is_equal(version:ffVer, test_version:"3.5.1")||
     version_is_equal(version:ffVer, test_version:"3.5.2"))
  {
    security_warning(0);
    exit(0);
  }
}

# Seamonkey Check
smVer = get_kb_item("Seamonkey/Linux/Ver");

if(smVer != NULL)
{
  # Grep for Seamonkey version 1.1.17
  if(version_is_equal(version:smVer, test_version:"1.1.17")){
    security_warning(0);
  }
}