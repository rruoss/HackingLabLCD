###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_thunderbird_mult_vuln_dec09_lin.nasl 15 2013-10-27 12:49:54Z jan $
#
# Thunderbird Multiple Vulnerabilities Dec-09 (Linux)
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
tag_impact = "Successful exploitation will let the attacker execute arbitrary code via
  unknown vectors or compromise a user's system.
  Impact Level: Application/System";
tag_affected = "Thunderbird version 3.0 and prior on Linux.";
tag_insight = "Memory corruption error due to multiple unspecified flaws in the browser
  engine, which can be exploited via unknown vectors.";
tag_solution = "Upgrade to Mozilla Thunderbird version 3.0.1 or later,
  For updates refer to http://www.mozillamessaging.com/en-US/thunderbird/";
tag_summary = "The host is installed with Thunderbird browser and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(902008);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_cve_id("CVE-2009-3979", "CVE-2009-3980", "CVE-2009-3981", "CVE-2009-3982");
  script_bugtraq_id(37361, 37362, 37363, 37364);
  script_name("Thunderbird Multiple Vulnerabilities Dec-09 (Linux)");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37699");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3547");
  script_xref(name : "URL" , value : "http://www.mozilla.org/security/announce/2009/mfsa2009-65.html");

  script_description(desc);
  script_summary("Check for the version of Thunderbird");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("General");
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

# Thunderbird Check
tbVer = get_kb_item("Thunderbird/Linux/Ver");
if(tbVer)
{
  # Grep for Thunderbird version 3.0 and prior
  if(version_is_less_equal(version:tbVer, test_version:"3.0")){
    security_hole(0);
  }
}
