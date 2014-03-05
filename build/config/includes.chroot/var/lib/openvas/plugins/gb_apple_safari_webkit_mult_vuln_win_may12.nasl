###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_webkit_mult_vuln_win_may12.nasl 12 2013-10-27 11:15:33Z jan $
#
# Apple Safari Webkit Multiple Vulnerabilities - May 12 (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
tag_impact = "Successful exploitation will allow attacker to conduct cross site
  scripting attacks, bypass certain security restrictions, and compromise
  a user's system.
  Impact Level: Application";
tag_affected = "Apple Safari versions prior to 5.1.7 on Windows";
tag_insight = "The flaws are due to
  - Multiple cross site scripting and memory corruption issues in webkit.
  - A state tracking issue existed in WebKit's handling of forms.";
tag_solution = "Upgrade to Apple Safari version 5.1.7 or later,
  For updates refer to http://www.apple.com/support/downloads/";
tag_summary = "The host is installed with Apple Safari web browser and is prone
  to multiple vulnerabilities.";

if(description)
{
  script_id(802796);
  script_version("$Revision: 12 $");
  script_cve_id("CVE-2011-3046", "CVE-2011-3056", "CVE-2012-0672", "CVE-2012-0676");
  script_bugtraq_id(52369, 53407, 53404, 53446);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"risk_factor", value:"Critical");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 12:15:33 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2012-05-18 19:02:04 +0530 (Fri, 18 May 2012)");
  script_name("Apple Safari Webkit Multiple Vulnerabilities - May 12 (Windows)");
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
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5282");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47292/");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2012/May/msg00002.html");

  script_description(desc);
  script_summary("Check for the version of Apple Safari on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
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

# Variable Initialization
safVer = "";

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

## Grep for Apple Safari Versions prior to 5.1.7(5.34.57.2)
if(version_is_less(version:safVer, test_version:"5.34.57.2")){
  security_hole(0);
}
