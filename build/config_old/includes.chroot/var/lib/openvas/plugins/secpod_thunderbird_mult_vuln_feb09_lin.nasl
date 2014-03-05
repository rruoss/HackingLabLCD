###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_thunderbird_mult_vuln_feb09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Mozilla Thunderbird Multiple Vulnerabilities Feb-09 (Linux)
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
tag_impact = "Successful exploitation may let the attacker cause remote code execution
  or may cause memory/application crash to conduct denial of service attack.
  Impact Level: System/Application";
tag_affected = "Thunderbird version prior to 2.0.0.21 on Linux.";
tag_insight = "Flaws are in vectors related to the layout engine and destruction of
  arbitrary layout objects by the 'nsViewManager::Composite' function.";
tag_solution = "Upgrade to Thunderbird version 2.0.0.21
  http://www.mozilla.com/en-US/thunderbird";
tag_summary = "The host is installed with Mozilla Thunderbird and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(900311);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-0352", "CVE-2009-0353");
  script_bugtraq_id(33598);
  script_name("Mozilla Thunderbird Multiple Vulnerabilities Feb-09 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33799");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-01.html");

  script_description(desc);
  script_summary("Check for the version of Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_thunderbird_detect_lin.nasl");
  script_require_keys("Thunderbird/Linux/Ver");
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

tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(!tbVer){
  exit(0);
}

# Grep for Thunderbird version < 2.0.0.21
if(version_is_less(version:tbVer, test_version:"2.0.0.21")){
  security_hole(0);
}
