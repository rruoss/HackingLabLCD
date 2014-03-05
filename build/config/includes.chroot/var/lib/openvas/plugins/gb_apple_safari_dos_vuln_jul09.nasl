###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_safari_dos_vuln_jul09.nasl 15 2013-10-27 12:49:54Z jan $
#
# Apple Safari Denial Of Service Vulnerability - Jul09
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
tag_impact = "Successful exploitation allow attackers to execute arbitrary code or can
  even crash the browser.
  Impact Level: Application";

tag_summary = "The host is installed with Apple Safari web browser and is prone
  to Denial of Service vulnerability.";

tag_affected = "Apple Safari 3.2.3 on Windows.";
tag_insight = "The flaws are due to
  - Error in 'CFCharacterSetInitInlineBuffer' method in CoreFoundation.dll
    when processing high-bit character in a URL fragment for an unspecified
    protocol.
  - Error in implementing the file 'protocol handler' when processing vectors
    involving an unspecified HTML tag.";
tag_solution = "No solution or patch is available as of 10th July, 2009. Information regarding
  this issue will be updated once the solution details are available.
  For updates refer to http://www.apple.com/support/downloads/";

if(description)
{
  script_id(800656);
  script_version("$Revision: 15 $");
  script_tag(name:"last_modification", value:"$Date: 2013-10-27 13:49:54 +0100 (Sun, 27 Oct 2013) $");
  script_tag(name:"creation_date", value:"2009-07-12 15:16:55 +0200 (Sun, 12 Jul 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"risk_factor", value:"High");
  script_cve_id("CVE-2009-2420", "CVE-2009-2421");
  script_name("Apple Safari Denial Of Service Vulnerability - Jul09");
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
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/504479");

  script_description(desc);
  script_summary("Check for the version of Apple Safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_safari_detect_win_900003.nasl");
  script_require_keys("AppleSafari/Version");
  if (revcomp(a: OPENVAS_VERSION, b: "6.0+beta5") >= 0) {
    script_tag(name : "affected" , value : tag_affected);
    script_tag(name : "insight" , value : tag_insight);
    script_tag(name : "solution" , value : tag_solution);
    script_tag(name : "summary" , value : tag_summary);
    script_tag(name : "impact" , value : tag_impact);
  }
  exit(0);
}


include("version_func.inc");

safVer = get_kb_item("AppleSafari/Version");
if(!safVer){
  exit(0);
}

# Grep for Apple Safari Version <= 3.2.3 (3.525.29.0)
if(version_is_equal(version:safVer, test_version:"3.525.29.0")){
   security_hole(0);
}
