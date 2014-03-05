###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_jsinfer_dos_vuln_macosx.nasl 12 2013-10-27 11:15:33Z jan $
#
# Mozilla Products 'jsinfer.cpp' Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_solution = "Upgrade to Mozilla Firefox ESR version 10.0.5 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html

  Upgrade to Mozilla Thunderbird ESR version 10.0.5 or later,
  http://www.mozilla.org/en-US/thunderbird/";

tag_impact = "Successful exploitation could allow attackers to execute arbitrary code in
  the context of the browser or cause a denial of service.
  Impact Level: System/Application";
tag_affected = "Thunderbird ESR version 10.x before 10.0.5,
  Mozilla Firefox ESR version 10.x before 10.0.5 on Mac OS X";
tag_insight = "The 'jsinfer.cpp' function in ESR versions fails to determine data types,
  which allows to cause a denial of service via crafted JavaScript code.";
tag_summary = "This host is installed with Mozilla firefox/thunderbird and is prone to
  denial of service vulnerability.";

if(description)
{
  script_id(802870);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2012-1939");
  script_bugtraq_id(53797);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-06-19 15:21:15 +0530 (Tue, 19 Jun 2012)");
  script_name("Mozilla Products 'jsinfer.cpp' Denial of Service Vulnerability (Mac OS X)");
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

  script_xref(name : "URL" , value : "http://secunia.com/advisories/49368");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49366");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027120");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2012/mfsa2012-34.html");

  script_description(desc);
  script_summary("Check for the version of Mozilla Firefox/Thunderbird on Mac OS X");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_require_keys("Mozilla/Firefox/MacOSX/Version",
                      "ThunderBird/MacOSX/Version");
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

# Firefox Check
ffVer = "";
ffVer = get_kb_item("Mozilla/Firefox/MacOSX/Version");

if(ffVer)
{
  # Grep for Firefox version
  if(version_in_range(version:ffVer, test_version:"10.0", test_version2:"10.0.4"))
  {
    security_hole(0);
    exit(0);
  }
}

# Thunderbird Check
tbVer = "";
tbVer = get_kb_item("ThunderBird/MacOSX/Version");

if(tbVer)
{
  # Grep for Thunderbird version
  if(version_in_range(version:tbVer, test_version:"10.0", test_version2:"10.0.4"))
  {
    security_hole(0);
    exit(0);
  }
}
