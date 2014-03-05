###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mozilla_prdts_mult_vuln05_jan13_win.nasl 11 2013-10-27 10:12:02Z jan $
#
# Mozilla Firefox Multiple Vulnerabilities-05 January13 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_impact = "Successful exploitation could allow attackers to cause a denial of service
  or execute arbitrary code in the context of the browser.
  Impact Level: System/Application";

tag_affected = "Mozilla Firefox version before 18.0 on Windows";
tag_insight = "- An error within the 'CharDistributionAnalysis::HandleOneChar()' can be
    exploited to cause a buffer overflow.
  - Unspecified error in the browser engine can be exploited to corrupt memory.";
tag_solution = "Upgrade to Mozilla Firefox version 18.0 or later,
  For updates refer to http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "This host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803206);
  script_version("$Revision: 11 $");
  script_cve_id("CVE-2013-0760", "CVE-2013-0770");
  script_bugtraq_id(57199, 57207);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 11:12:02 +0100 (So, 27. Okt 2013) $");
  script_tag(name:"creation_date", value:"2013-01-16 17:04:59 +0530 (Wed, 16 Jan 2013)");
  script_name("Mozilla Firefox Multiple Vulnerabilities-05 January13 (Windows)");
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
  script_xref(name : "URL" , value : "http://www.osvdb.org/89012");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51752");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027955");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-01.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2013/mfsa2013-02.html");

  script_description(desc);
  script_summary("Check for the vulnerable version of Mozilla Firefox on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0){
    script_tag(name : "impact" , value : tag_impact);
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
  }
  exit(0);
}


include("version_func.inc");

ffVer = "";

# Firefox Check
ffVer = get_kb_item("Firefox/Win/Ver");
if(!ffVer){
  exit(0);
}

# Grep for Firefox version
if(version_is_less(version:ffVer, test_version:"18.0")){
  security_hole(0);
}
