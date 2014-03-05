###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_k-meleon_addr_bar_spoofing_vuln.nasl 15 2013-10-27 12:49:54Z jan $
#
# K-Meleon Address Bar Spoofing Vulnerability
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
tag_affected = "K-Meleon Browser version 1.5.3 on Windows.";
tag_insight = "Address bar can be spoofed via 'window.open()' with a relative URI, to show
  an arbitrary URL on the web site visited by the victim, as demonstrated by a
  visit to an attacker-controlled web page, which triggers a spoofed login form
  for the site containing that page.";
tag_solution = "No solution or patch is available as of 04th September 2009, Information
  regarding this issue will be updated once the solution details are available.
  For updates refer to http://kmeleon.sourceforge.net/";
tag_summary = "This host is installed with K-Meleon Browser and is prone to Address
  Bar Spoofing vulnerability.";

if(description)
{
  script_id(800892);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-09-08 18:25:53 +0200 (Tue, 08 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"risk_factor", value:"Medium");
  script_cve_id("CVE-2009-3008");
  script_name("K-Meleon Address Bar Spoofing Vulnerability");
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
  script_summary("Check for the version of K-Meleon Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_k-meleon_detect.nasl");
  script_require_keys("K-Meleon/Ver");
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

kmeleonVer = get_kb_item("K-Meleon/Ver");
if(kmeleonVer)
{
  # Check for K-Meleon Browser version 1.5.3
  if(version_is_equal(version:kmeleonVer, test_version:"1.5.3")){
    security_warning(0);
  }
}
