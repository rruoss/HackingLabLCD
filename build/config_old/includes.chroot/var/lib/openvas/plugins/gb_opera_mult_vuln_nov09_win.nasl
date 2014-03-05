###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_opera_mult_vuln_nov09_win.nasl 15 2013-10-27 12:49:54Z jan $
#
# Opera Multiple Vulnerabilities - Nov09 (Win)
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
tag_impact = "Attacker can exploit this issue to disclose sensitive information, conduct
  spoofing attacks, Denial of Service or compromise a user's system.
  Impact Level: Application";
tag_affected = "Opera version prior to 10.01 on Windows.";
tag_insight = "- An error when processing domain names can be exploited to cause a memory
    corruption.
  - An error when processing web fonts can be exploited to change the font of
    the address field and display an arbitrary domain name as an address.";
tag_solution = "Upgrade to Opera version 10.01 or later
  http://www.opera.com/browser/download/";
tag_summary = "This host is installed with Opera Web Browser and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(801140);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3831", "CVE-2009-3832");
  script_bugtraq_id(36850);
  script_name("Opera Multiple Vulnerabilities - Nov09 (Win)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37182");
  script_xref(name : "URL" , value : "http://www.opera.com/support/kb/view/938/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3073");
  script_xref(name : "URL" , value : "http://www.opera.com/docs/changelogs/windows/1001");

  script_description(desc);
  script_summary("Check for the version of Opera Web Browser");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
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

operaVer = get_kb_item("Opera/Win/Version");
if(operaVer)
{
  # Check for Opera Version < 10.1 (10.01)
  if(version_is_less(version:operaVer, test_version:"10.1")){
    security_hole(0);
  }
}
