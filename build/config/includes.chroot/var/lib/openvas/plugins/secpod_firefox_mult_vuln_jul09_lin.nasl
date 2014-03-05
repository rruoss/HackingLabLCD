###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_firefox_mult_vuln_jul09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Firefox Multiple Vulnerabilities July-09 (Linux)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary code,
  memory corruption, XSS attacks and results in Denial of Service condition.
  Impact Level: System/Application";
tag_affected = "Mozilla Firefox version prior to 3.0.12 on Linux.";
tag_insight = "Multiple flaws are reported in Firefox, for more information refer below
  reference links.";
tag_solution = "Upgrade to Firefox version 3.0.12 or 3.5 or later
  http://www.mozilla.com/en-US/firefox/all.html";
tag_summary = "The host is installed with Firefox browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(900397);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-23 21:05:26 +0200 (Thu, 23 Jul 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464",
                "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2469",
                "CVE-2009-2471", "CVE-2009-2472");
  script_bugtraq_id(35765, 35769, 35775, 35770, 35776, 35772, 35766, 35773);
  script_name("Mozilla Firefox Multiple Vulnerabilities July-09 (Linux)");
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
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1972");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-34.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-37.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-39.html");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-40.html");

  script_description(desc);
  script_summary("Check for the Version of Firefox");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_require_keys("Firefox/Linux/Ver");
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

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer){
  exit(0);
}

# Grep for Firefox version < 3.0.12
if(version_is_less(version:ffVer, test_version:"3.0.12")){
  security_hole(0);
}
